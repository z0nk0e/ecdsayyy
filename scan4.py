#!/usr/bin/env python3
"""
nonce_graph_all_with_taproot_full.py

Graph-based detection and (non-mainnet) derivation of secrets from:
- ECDSA inputs: P2PKH, P2WPKH, P2SH-P2WPKH, P2PK, bare multisig, P2SH multisig, P2WSH multisig.
- Taproot key-path (Schnorr BIP340/341): equations s = k_r + e·x_Q (mod n).

Ethics/safety:
- Mainnet: detection-only. Reports duplicate nonces, solvable components (full rank), and cycles.
- Testnet/Regtest: solvers enabled with --solve; outputs recovered secrets if requested.

Dependencies:
- pip install requests python-bitcoinlib coincurve btclib
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

# ECDSA (legacy/segwit-v0)
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
    CC_PublicKey = None
    CC_PrivateKey = None
    HAS_COINCURVE = False

# BIP341 (Taproot) sighash via btclib
try:
    import btclib
    from btclib.tx import Tx as BTCLIB_Tx
    import importlib
    btclib_taproot_sighash = None
    # try known locations for taproot_sighash across btclib versions
    for modname in ('btclib.tx.signtx', 'btclib.tx.sighash', 'btclib.tx.taproot'):
        try:
            mod = importlib.import_module(modname)
            if hasattr(mod, 'taproot_sighash'):
                btclib_taproot_sighash = getattr(mod, 'taproot_sighash')
                break
        except Exception:
            continue
    HAS_BTCLIB = True
except Exception:
    HAS_BTCLIB = False
    BTCLIB_Tx = None
    btclib_taproot_sighash = None

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ---------- Utilities ----------

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
    if len(pubkey_bytes) == 33 and pubkey_bytes[0] in (2, 3):
        return pubkey_bytes
    if len(pubkey_bytes) == 65 and pubkey_bytes[0] == 4:
        x_bytes = pubkey_bytes[1:33]
        y_bytes = pubkey_bytes[33:65]
        y_int = int_from_be(y_bytes)
        prefix = 2 if (y_int % 2 == 0) else 3
        return bytes([prefix]) + x_bytes
    return pubkey_bytes

def parse_der_signature(der_sig: bytes) -> Tuple[int, int]:
    if len(der_sig) < 8 or der_sig[0] != 0x30:
        raise ValueError("Bad DER: missing SEQUENCE")
    i = 2
    if i >= len(der_sig) or der_sig[i] != 0x02:
        raise ValueError("Bad DER: r tag")
    i += 1
    if i >= len(der_sig):
        raise ValueError("Bad DER: r len")
    r_len = der_sig[i]; i += 1
    r = int_from_be(der_sig[i:i+r_len]); i += r_len
    if i >= len(der_sig) or der_sig[i] != 0x02:
        raise ValueError("Bad DER: s tag")
    i += 1
    if i >= len(der_sig):
        raise ValueError("Bad DER: s len")
    s_len = der_sig[i]; i += 1
    s = int_from_be(der_sig[i:i+s_len]); i += s_len
    return (r, s)

def base58_encode(b: bytes) -> str:
    alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(b, 'big')
    out = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        out.append(alphabet[rem])
    pad = 0
    for ch in b:
        if ch == 0:
            pad += 1
        else:
            break
    return (alphabet[0:1] * pad + out[::-1]).decode()

def privkey_to_wif(d: int, compressed: bool = True, testnet: bool = True) -> str:
    if not (1 <= d < SECP256K1_N):
        raise ValueError("Invalid private key range")
    version = b'\xEF' if testnet else b'\x80'
    payload = version + d.to_bytes(32, 'big') + (b'\x01' if compressed else b'')
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)

def is_der_sig_push(b: bytes) -> bool:
    return len(b) >= 9 and b[0] == 0x30

def tagged_hash(tag: str, msg: bytes) -> bytes:
    t = sha256(tag.encode())
    return sha256(t + t + msg)

# ---------- RPC ----------

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

    def getblockhash(self, height: int) -> str:
        return self.call("getblockhash", [height])

    def getblock(self, blockhash: str, verbosity: int = 2):
        return self.call("getblock", [blockhash, verbosity])

    def getrawtransaction(self, txid: str, verbose: bool = True):
        return self.call("getrawtransaction", [txid, int(bool(verbose))])

    def getrawmempool(self) -> List[str]:
        return self.call("getrawmempool", [])

    def getblockchaininfo(self) -> dict:
        return self.call("getblockchaininfo", [])

# ---------- Data structures ----------

@dataclass
class ECDSASigEdge:
    # ECDSA equation: s * k_r - r * x_Q = z  (mod n)
    r: int
    s: int
    z: int
    sighash_type: int
    pubkey_hex: str
    txid: str
    vin: int
    is_witness: bool
    script_type: str

@dataclass
class SchnorrSigEdge:
    # Schnorr (Taproot key-path): k_r + e * x_Q = s  (mod n)
    r_x: int
    s: int
    e: int
    sighash_type: int
    pubkey_xonly_hex: str
    txid: str
    vin: int
    script_type: str

@dataclass
class LeakFinding:
    kind: str
    detail: dict

# ---------- ECDSA extractors (singlesig + multisig) ----------

class P2WPKHExtractor:
    def extract(self, tx_json: dict, vin_idx: int) -> List[Tuple[bytes, bytes, bool, str]]:
        vin = tx_json["vin"][vin_idx]
        out = []
        wit = vin.get("txinwitness")
        if isinstance(wit, list) and len(wit) >= 2:
            sig_hex = wit[0]; pub_hex = wit[-1]
            try:
                sig = bytes.fromhex(sig_hex); pub = bytes.fromhex(pub_hex)
                if len(pub) in (33, 65) and is_der_sig_push(sig):
                    out.append((sig, pub, True, "p2wpkh-like"))
            except Exception:
                pass
        return out

class P2PKHExtractor:
    def _parse_pushes(self, script_bytes: bytes) -> List[bytes]:
        out = []
        i = 0; n = len(script_bytes)
        while i < n:
            op = script_bytes[i]; i += 1
            if op == 0:
                out.append(b"")
            elif 1 <= op <= 75:
                out.append(script_bytes[i:i+op]); i += op
            elif op == 76 and i < n:
                l = script_bytes[i]; i += 1
                out.append(script_bytes[i:i+l]); i += l
            elif op == 77 and i+2 <= n:
                l = int.from_bytes(script_bytes[i:i+2], "little"); i += 2
                out.append(script_bytes[i:i+l]); i += l
            elif op == 78 and i+4 <= n:
                l = int.from_bytes(script_bytes[i:i+4], "little"); i += 4
                out.append(script_bytes[i:i+l]); i += l
            else:
                pass
        return out

    def extract(self, tx_json: dict, vin_idx: int) -> List[Tuple[bytes, bytes, bool, str]]:
        vin = tx_json["vin"][vin_idx]
        out = []
        ss_hex = vin.get("scriptSig", {}).get("hex")
        if ss_hex:
            try:
                items = self._parse_pushes(bytes.fromhex(ss_hex))
                if len(items) >= 2 and len(items[-1]) in (33, 65) and is_der_sig_push(items[0]):
                    out.append((items[0], items[-1], False, "p2pkh"))
            except Exception:
                pass
        return out

# ---------- Taproot key-path extractor ----------

class TaprootKeypathExtractor:
    def __init__(self):
        self.enabled = HAS_BTCLIB and HAS_COINCURVE

    def is_p2tr_spk(self, spk_hex: str) -> bool:
        try:
            b = bytes.fromhex(spk_hex)
            return len(b) == 34 and b[0] == 0x51 and b[1] == 0x20
        except Exception:
            return False

    def extract_edges(self, tx_json: dict, rawtx_hex: str, prevouts: List[Tuple[int, str]], txid: str) -> List[SchnorrSigEdge]:
        if not self.enabled:
            return []
        edges: List[SchnorrSigEdge] = []
        vins = tx_json.get("vin", [])
        try:
            tx_b = BTCLIB_Tx.from_bytes(bytes.fromhex(rawtx_hex))
        except Exception:
            return []

        for vin_idx, vin in enumerate(vins):
            wit = vin.get("txinwitness")
            if not (isinstance(wit, list) and len(wit) >= 1):
                continue
            sig_hex = wit[0]
            try:
                sig_bytes = bytes.fromhex(sig_hex)
            except Exception:
                continue
            if len(sig_bytes) == 64:
                sighash_type = 0x00
                sig_raw = sig_bytes
            elif len(sig_bytes) == 65:
                sighash_type = sig_bytes[-1]
                sig_raw = sig_bytes[:64]
            else:
                continue
            base_type = sighash_type & 0x03
            anyonecanpay = (sighash_type & 0x80) != 0
            if base_type not in (0x00, 0x01) or anyonecanpay:
                continue

            amt_spk = prevouts[vin_idx] if vin_idx < len(prevouts) else None
            if not amt_spk:
                continue
            amount_sats, spk_hex = amt_spk
            if not self.is_p2tr_spk(spk_hex):
                continue
            P_x = bytes.fromhex(spk_hex[4:])
            if len(P_x) != 32:
                continue

            try:
                spent_outputs = []
                for (amt, spk) in prevouts:
                    spent_outputs.append((amt, bytes.fromhex(spk)))
                msg32 = btclib_taproot_sighash(tx_b, vin_idx, sighash_type, spent_outputs)
            except Exception:
                continue

            r_bytes = sig_raw[:32]; s_bytes = sig_raw[32:]
            e_bytes = tagged_hash("BIP0340/challenge", r_bytes + P_x + msg32)
            e = int_from_be(e_bytes) % SECP256K1_N
            s = int_from_be(s_bytes) % SECP256K1_N
            r_x = int_from_be(r_bytes) % SECP256K1_N

            try:
                CC_PublicKey.from_xonly(P_x).verify_schnorr(sig_raw, msg32)
            except Exception:
                continue

            edges.append(SchnorrSigEdge(
                r_x=r_x, s=s, e=e, sighash_type=sighash_type,
                pubkey_xonly_hex=P_x.hex(), txid=txid, vin=vin_idx, script_type="p2tr-keypath"
            ))
        return edges

# ---------- ECDSA analyzer (full coverage) ----------

class ECDSANonceAnalyzer:
    def __init__(self, rpc: BitcoinRPC, max_cycle_length: int = 8):
        self.rpc = rpc
        self.max_cycle_length = max_cycle_length
        self.singlesig_extractors = [P2WPKHExtractor(), P2PKHExtractor()]
        self.edges: List[ECDSASigEdge] = []
        self.edges_by_rq: Dict[Tuple[int, str], List[ECDSASigEdge]] = defaultdict(list)
        self.edges_by_r: Dict[int, List[ECDSASigEdge]] = defaultdict(list)
        self.edges_by_q: Dict[str, List[ECDSASigEdge]] = defaultdict(list)
        self.unique_r = set()
        self.unique_q = set()
        self._prevout_cache: Dict[Tuple[str, int], Tuple[int, str]] = {}

    def _p2pkh_script_code(self, pubkey_bytes: bytes) -> CScript:
        return CScript([OP_DUP, OP_HASH160, hash160(pubkey_bytes), OP_EQUALVERIFY, OP_CHECKSIG])

    def _compute_z(self, rawtx_hex: str, vin_index: int, sighash_type: int,
                   script_code: CScript, amount_sats: int, is_witness: bool) -> int:
        ctx = CTransaction()
        ctx.deserialize(x(rawtx_hex))

        # Call SignatureHash in a way compatible with multiple python-bitcoinlib versions:
        # - Some versions accept named amount and sigversion.
        # - Others accept amount positionally for segwit, or only the legacy signature.
        # Try several call forms and normalize the result.
        # If one succeeds, return the computed z immediately to avoid subtle tuple/index issues.

        def _extract_digest(obj):
            # Recursively search tuples/lists for a usable digest element.
            if obj is None:
                return None
            if isinstance(obj, (bytes, bytearray, memoryview)):
                b = bytes(obj)
                if len(b) == 32:
                    return b
                # sometimes the digest may be returned with other metadata; skip if wrong len
                return None
            if isinstance(obj, int):
                try:
                    return int(obj).to_bytes(32, "big")
                except Exception:
                    return None
            if isinstance(obj, (tuple, list)):
                for it in obj:
                    b = _extract_digest(it)
                    if b is not None:
                        return b
                return None
            # Unknown type
            return None

        attempts = []
        if is_witness:
            attempts = [
                lambda: SignatureHash(script_code, ctx, vin_index, sighash_type, amount=amount_sats, sigversion=SIGVERSION_WITNESS_V0),
                lambda: SignatureHash(script_code, ctx, vin_index, sighash_type, amount=amount_sats),
                lambda: SignatureHash(script_code, ctx, vin_index, sighash_type, amount_sats, SIGVERSION_WITNESS_V0),
                lambda: SignatureHash(script_code, ctx, vin_index, sighash_type),
            ]
        else:
            attempts = [
                lambda: SignatureHash(script_code, ctx, vin_index, sighash_type),
            ]

        last_exception = None
        for fn in attempts:
            try:
                res = fn()
                digest_bytes = _extract_digest(res)
                if digest_bytes is None:
                    # This attempt did not yield a valid 32-byte digest; try next
                    continue
                return int_from_be(digest_bytes) % SECP256K1_N

            except TypeError:
                # wrong signature for this variant; try next
                continue
            except Exception as e:
                # store last meaningful exception and try other attempts
                last_exception = e
                continue

        # If all attempts failed, raise the last known meaningful exception or a generic one.
        if last_exception:
            raise last_exception
        raise RuntimeError("Could not compute sighash z for tx")

    def _get_prevout(self, prev_txid: str, prev_vout: int) -> Optional[Tuple[int, str]]:
        key = (prev_txid, prev_vout)
        if key in self._prevout_cache:
            return self._prevout_cache[key]
        try:
            prev_json = self.rpc.getrawtransaction(prev_txid, True)
            vout = prev_json["vout"][prev_vout]
            sats = int(round(float(vout["value"]) * 100_000_000))
            spk_hex = vout["scriptPubKey"]["hex"]
            self._prevout_cache[key] = (sats, spk_hex)
            return sats, spk_hex
        except Exception:
            return None

    def _add_edge(self, edge: ECDSASigEdge):
        self.edges.append(edge)
        self.unique_r.add(edge.r)
        self.unique_q.add(edge.pubkey_hex)
        self.edges_by_rq[(edge.r, edge.pubkey_hex)].append(edge)
        self.edges_by_r[edge.r].append(edge)
        self.edges_by_q[edge.pubkey_hex].append(edge)

    def _parse_script(self, hex_str: str) -> List[Union[int, bytes]]:
        try:
            return list(CScript(bytes.fromhex(hex_str)))
        except Exception:
            return []

    def _extract_multisig(self, vin: dict, prev_spk_hex: str) -> Tuple[List[bytes], bytes, str, bool, int]:
        """
        Return (der_sigs, script_code_bytes, script_type, is_witness, amount_sats) for multisig, or empty if not.
        Handles:
          - P2WSH multisig (witness: sig..., witnessScript)
          - P2SH multisig (scriptSig: OP_0 sig... redeemScript)
          - Bare multisig (prevout SPK is multisig; scriptSig: OP_0 sig...)
        """
        # P2WSH multisig
        wit = vin.get("txinwitness")
        if isinstance(wit, list) and len(wit) >= 2:
            witness_script = bytes.fromhex(wit[-1])
            items = self._parse_script(witness_script.hex())
            if items and isinstance(items[-1], int) and items[-1] == OP_CHECKMULTISIG:
                sigs = []
                for w in wit[:-1]:
                    try:
                        b = bytes.fromhex(w)
                        if is_der_sig_push(b):
                            sigs.append(b)
                    except Exception:
                        pass
                return sigs, witness_script, "p2wsh-multisig", True, None  # amount filled later

        # P2SH multisig
        ss_hex = vin.get("scriptSig", {}).get("hex") or ""
        if ss_hex:
            b = bytes.fromhex(ss_hex)
            # parse pushes
            items = []
            i = 0; n = len(b)
            while i < n:
                op = b[i]; i += 1
                if 1 <= op <= 75 and i+op <= n:
                    items.append(b[i:i+op]); i += op
                elif op == 0:
                    items.append(b"")
                elif op == 76 and i < n:
                    l = b[i]; i += 1
                    items.append(b[i:i+l]); i += l
                elif op == 77 and i+2 <= n:
                    l = int.from_bytes(b[i:i+2], 'little'); i += 2
                    items.append(b[i:i+l]); i += l
                else:
                    pass
            if len(items) >= 2:
                redeem = items[-1]
                rs_items = self._parse_script(redeem.hex())
                if rs_items and isinstance(rs_items[-1], int) and rs_items[-1] == OP_CHECKMULTISIG:
                    sigs = [it for it in items[:-1] if is_der_sig_push(it)]
                    return sigs, redeem, "p2sh-multisig", False, None

        # Bare multisig (prevout is multisig)
        prev_items = self._parse_script(prev_spk_hex)
        if prev_items and isinstance(prev_items[-1], int) and prev_items[-1] == OP_CHECKMULTISIG:
            if ss_hex:
                b = bytes.fromhex(ss_hex)
                sigs = []
                i = 0; n = len(b)
                while i < n:
                    op = b[i]; i += 1
                    if 1 <= op <= 75 and i+op <= n:
                        data = b[i:i+op]; i += op
                        if is_der_sig_push(data):
                            sigs.append(data)
                    elif op == 0:
                        pass
                    elif op == 76 and i < n:
                        l = b[i]; i += 1
                        data = b[i:i+l]; i += l
                        if is_der_sig_push(data):
                            sigs.append(data)
                    elif op == 77 and i+2 <= n:
                        l = int.from_bytes(b[i:i+2], 'little'); i += 2
                        data = b[i:i+l]; i += l
                        if is_der_sig_push(data):
                            sigs.append(data)
                return sigs, bytes.fromhex(prev_spk_hex), "bare-multisig", False, None

        return [], b"", "", False, None

    def collect_from_txids(self, txids: Iterable[str]) -> None:
        for txid in txids:
            try:
                tx_json = self.rpc.getrawtransaction(txid, True)
                raw_hex = self.rpc.getrawtransaction(txid, False)
            except Exception as e:
                print(f"RPC error for {txid}: {e}", file=sys.stderr)
                continue

            vins = tx_json.get("vin", [])
            for vin_idx, vin in enumerate(vins):
                prev_txid = vin.get("txid"); prev_vout = vin.get("vout")
                if prev_txid is None or prev_vout is None:
                    continue
                prev = self._get_prevout(prev_txid, prev_vout)
                if not prev:
                    print(f"Warning: prevout {prev_txid}:{prev_vout} not found for {txid}:{vin_idx}", file=sys.stderr)
                    continue
                amount_sats, spk_hex = prev

                # Singlesig: P2WPKH/P2PKH
                for ex in self.singlesig_extractors:
                    for sig_with_type, pubkey, is_wit, stype in ex.extract(tx_json, vin_idx):
                        sighash_type = sig_with_type[-1]
                        der = sig_with_type[:-1]
                        try:
                            r, s = parse_der_signature(der)
                        except Exception:
                            continue
                        pub_c = compress_pubkey(pubkey)
                        script_code = self._p2pkh_script_code(pub_c)
                        try:
                            z = self._compute_z(raw_hex, vin_idx, sighash_type, script_code, amount_sats if is_wit else 0, is_wit)
                        except Exception as e:
                            print(f"Warning: z compute failed {txid}:{vin_idx} -> {e}", file=sys.stderr)
                            continue
                        self._add_edge(ECDSASigEdge(
                            r=r % SECP256K1_N, s=s % SECP256K1_N, z=z,
                            sighash_type=sighash_type, pubkey_hex=pub_c.hex(),
                            txid=txid, vin=vin_idx, is_witness=is_wit, script_type=stype
                        ))

                # P2PK legacy
                spk_items = self._parse_script(spk_hex)
                if len(spk_items) == 2 and isinstance(spk_items[0], (bytes, bytearray)) and spk_items[1] == OP_CHECKSIG:
                    ss_hex = vin.get("scriptSig", {}).get("hex") or ""
                    b = bytes.fromhex(ss_hex) if ss_hex else b""
                    if b:
                        i = 0
                        if i < len(b):
                            op = b[i]; i += 1
                            if 1 <= op <= 75 and i+op <= len(b):
                                sig_with_type = b[i:i+op]
                                if is_der_sig_push(sig_with_type):
                                    sighash_type = sig_with_type[-1]; der = sig_with_type[:-1]
                                    try:
                                        r, s = parse_der_signature(der)
                                    except Exception:
                                        r = s = None
                                    if r is not None:
                                        pub_c = compress_pubkey(bytes(spk_items[0]))
                                        sc = CScript([bytes(spk_items[0]), OP_CHECKSIG])
                                        try:
                                            z = self._compute_z(rawtx_hex=raw_hex, vin_index=vin_idx, sighash_type=sighash_type, script_code=sc, amount_sats=0, is_witness=False)
                                        except Exception:
                                            z = None
                                        if z is not None:
                                            self._add_edge(ECDSASigEdge(
                                                r=r % SECP256K1_N, s=s % SECP256K1_N, z=z,
                                                sighash_type=sighash_type, pubkey_hex=pub_c.hex(),
                                                txid=txid, vin=vin_idx, is_witness=False, script_type="p2pk"
                                            ))

                # Multisig (bare / P2SH / P2WSH)
                der_sigs, script_code_bytes, ms_type, is_wit_ms, _ = self._extract_multisig(vin, spk_hex)
                if der_sigs and script_code_bytes:
                    # Compute z once per input (same for all sigs in that input)
                    try:
                        sighash_types = [sig[-1] for sig in der_sigs]
                        # Use the first sighash byte to compute z; in standard multisig all sigs share the same sighash
                        sighash_type = sighash_types[0]
                        z = self._compute_z(rawtx_hex=raw_hex, vin_index=vin_idx, sighash_type=sighash_type, script_code=CScript(script_code_bytes), amount_sats=amount_sats if is_wit_ms else 0, is_witness=is_wit_ms)
                        z_bytes = z.to_bytes(32, 'big')
                    except Exception as e:
                        print(f"Warning: z compute (multisig) failed {txid}:{vin_idx} -> {e}", file=sys.stderr)
                        continue

                    # Collect pubkeys from script
                    pubs = [bytes(it) for it in self._parse_script(script_code_bytes.hex())
                            if isinstance(it, (bytes, bytearray)) and len(it) in (33, 65)]

                    for sig_with_type in der_sigs:
                        der = sig_with_type[:-1]
                        try:
                            r, s = parse_der_signature(der)
                        except Exception:
                            continue
                        matched_pub = None
                        if HAS_COINCURVE:
                            for p in pubs:
                                try:
                                    if CC_PublicKey(compress_pubkey(p)).verify(der, z_bytes, hasher=None):
                                        matched_pub = compress_pubkey(p); break
                                except Exception:
                                    continue
                        # Fallback to order-based mapping if verification not available
                        if matched_pub is None and pubs:
                            matched_pub = compress_pubkey(pubs[0])
                            pubs = pubs[1:]  # shift so we don't reuse the same pub repeatedly

                        if matched_pub is None:
                            continue
                        self._add_edge(ECDSASigEdge(
                            r=r % SECP256K1_N, s=s % SECP256K1_N, z=z,
                            sighash_type=sighash_type, pubkey_hex=matched_pub.hex(),
                            txid=txid, vin=vin_idx, is_witness=is_wit_ms, script_type=ms_type
                        ))

    def collect_from_block_range(self, start_height: int, end_height: int):
        for h in range(start_height, end_height + 1):
            try:
                bh = self.rpc.getblockhash(h)
                blk = self.rpc.getblock(bh, 2)
            except Exception as e:
                print(f"RPC error at height {h}: {e}", file=sys.stderr)
                continue
            self.collect_from_txids([tx["txid"] for tx in blk.get("tx", [])])

    def collect_from_mempool(self):
        try:
            txids = self.rpc.getrawmempool()
        except Exception as e:
            print(f"RPC error getrawmempool: {e}", file=sys.stderr)
            return
        self.collect_from_txids(txids)

    # Graph + detection

    def detect_duplicate_rq(self) -> List[LeakFinding]:
        findings = []
        for (r, q), edges in self.edges_by_rq.items():
            if len(edges) < 2:
                continue
            uniq = {(e.s, e.z, e.sighash_type) for e in edges}
            if len(uniq) >= 2:
                findings.append(LeakFinding(
                    kind="ecdsa_duplicate_rq",
                    detail={"r": str(r), "pubkey": q, "count": len(edges),
                            "examples": [{"txid": e.txid, "vin": e.vin, "s": str(e.s), "z": str(e.z)} for e in edges[:6]]}
                ))
        return findings

    def _build_component_matrices(self):
        # Unknowns: [k_r for r] + [x_q for q]; eq: s*k_r - r*x_q = z
        adj = defaultdict(list)
        edge_map = defaultdict(list)
        for e in self.edges:
            rn = ('r', e.r); qn = ('q', e.pubkey_hex)
            adj[rn].append(qn); adj[qn].append(rn)
            edge_map[(rn, qn)].append(e)

        visited, components = set(), []

        def bfs(start):
            comp = set(); dq = deque([start]); visited.add(start)
            while dq:
                u = dq.popleft(); comp.add(u)
                for v in adj[u]:
                    if v not in visited:
                        visited.add(v); dq.append(v)
            return comp

        for node in list(adj.keys()):
            if node in visited: continue
            comp_nodes = bfs(node)
            r_nodes = sorted([n for n in comp_nodes if n[0] == 'r'], key=lambda x: x[1])
            q_nodes = sorted([n for n in comp_nodes if n[0] == 'q'], key=lambda x: x[1])
            idx_r = {r_nodes[i]: i for i in range(len(r_nodes))}
            idx_q = {q_nodes[i]: i for i in range(len(q_nodes))}
            A, b, used = [], [], []
            for rn in r_nodes:
                for qn in adj[rn]:
                    if qn[0] != 'q': continue
                    for e in edge_map[(rn, qn)]:
                        row = [0] * (len(r_nodes) + len(q_nodes))
                        row[idx_r[rn]] = e.s % SECP256K1_N
                        row[len(r_nodes) + idx_q[qn]] = (-e.r) % SECP256K1_N
                        A.append(row); b.append(e.z % SECP256K1_N); used.append(e)
            components.append((A, b, r_nodes, q_nodes, used))
        return components

    def _modular_rank(self, A: List[List[int]]) -> int:
        if not A: return 0
        m = [row[:] for row in A]
        rows, cols = len(m), len(m[0]); rank, col = 0, 0
        for r in range(rows):
            while col < cols and all(m[i][col] % SECP256K1_N == 0 for i in range(r, rows)):
                col += 1
            if col == cols: break
            pivot = None
            for i in range(r, rows):
                if m[i][col] % SECP256K1_N != 0:
                    pivot = i; break
            if pivot is None: col += 1; continue
            if pivot != r: m[r], m[pivot] = m[pivot], m[r]
            inv = modinv(m[r][col])
            m[r] = [(v * inv) % SECP256K1_N for v in m[r]]
            for i in range(rows):
                if i != r and m[i][col] != 0:
                    f = m[i][col] % SECP256K1_N
                    m[i] = [(m[i][j] - f * m[r][j]) % SECP256K1_N for j in range(cols)]
            rank += 1; col += 1
        return rank

    def detect_solvable_components(self) -> List[LeakFinding]:
        findings = []
        for A, b, r_nodes, q_nodes, used_edges in self._build_component_matrices():
            unknowns, eqs = len(r_nodes) + len(q_nodes), len(A)
            if unknowns == 0 or eqs < unknowns: continue
            if self._modular_rank(A) == unknowns:
                findings.append(LeakFinding(
                    kind="ecdsa_solvable_component",
                    detail={
                        "unknowns": unknowns, "equations": eqs,
                        "r_nodes": [n[1] for n in r_nodes],
                        "q_nodes": [n[1] for n in q_nodes],
                        "sample_edges": [{"txid": e.txid, "vin": e.vin, "r": str(e.r), "s": str(e.s), "z": str(e.z), "pubkey": e.pubkey_hex} for e in used_edges[:10]],
                    }
                ))
        return findings

    def find_cycles(self, max_len: int = 8) -> List[list]:
        adj = defaultdict(list)
        for e in self.edges:
            rn = ('r', e.r); qn = ('q', e.pubkey_hex)
            adj[rn].append(qn); adj[qn].append(rn)

        cycles, seen = [], set()

        def dfs(path, target, depth_left):
            cur = path[-1]
            if depth_left == 0:
                if cur == target and len(path) >= 4 and len(path) % 2 == 0:
                    key = tuple(path)
                    if key not in seen:
                        seen.add(key); cycles.append(list(path))
                return
            for nxt in adj[cur]:
                if len(path) >= 2 and nxt == path[-2]: continue
                if nxt in path and nxt != target: continue
                if path[-1][0] == nxt[0]: continue
                dfs(path + [nxt], target, depth_left - 1)

        for r in sorted(self.unique_r):
            start = ('r', r)
            for L in range(4, max_len + 1, 2):
                dfs([start], start, L)
        return cycles

# ---------- Taproot analyzer ----------

class SchnorrNonceAnalyzer:
    def __init__(self, rpc: BitcoinRPC, max_cycle_length: int = 8):
        self.rpc = rpc
        self.max_cycle_length = max_cycle_length
        self.tap = TaprootKeypathExtractor()
        self.edges: List[SchnorrSigEdge] = []
        self.edges_by_rq: Dict[Tuple[int, str], List[SchnorrSigEdge]] = defaultdict(list)
        self.edges_by_r: Dict[int, List[SchnorrSigEdge]] = defaultdict(list)
        self.edges_by_q: Dict[str, List[SchnorrSigEdge]] = defaultdict(list)
        self.unique_r = set()
        self.unique_q = set()
        self._prevout_cache: Dict[Tuple[str, int], Tuple[int, str]] = {}

    def _get_prevout(self, prev_txid: str, prev_vout: int) -> Optional[Tuple[int, str]]:
        key = (prev_txid, prev_vout)
        if key in self._prevout_cache:
            return self._prevout_cache[key]
        try:
            prev_json = self.rpc.getrawtransaction(prev_txid, True)
            vout = prev_json["vout"][prev_vout]
            sats = int(round(float(vout["value"]) * 100_000_000))
            spk_hex = vout["scriptPubKey"]["hex"]
            self._prevout_cache[key] = (sats, spk_hex)
            return sats, spk_hex
        except Exception:
            return None

    def _add_edge(self, e: SchnorrSigEdge):
        self.edges.append(e)
        self.unique_r.add(e.r_x); self.unique_q.add(e.pubkey_xonly_hex)
        self.edges_by_rq[(e.r_x, e.pubkey_xonly_hex)].append(e)
        self.edges_by_r[e.r_x].append(e)
        self.edges_by_q[e.pubkey_xonly_hex].append(e)

    def collect_from_txids(self, txids: Iterable[str]) -> None:
        if not self.tap.enabled:
            print("Taproot disabled: pip install btclib coincurve", file=sys.stderr)
            return
        for txid in txids:
            try:
                tx_json = self.rpc.getrawtransaction(txid, True)
                raw_hex = self.rpc.getrawtransaction(txid, False)
            except Exception as e:
                print(f"RPC error for {txid}: {e}", file=sys.stderr)
                continue
            vins = tx_json.get("vin", [])
            prevouts = []
            ok = True
            for vin in vins:
                prev_txid = vin.get("txid"); prev_vout = vin.get("vout")
                if prev_txid is None or prev_vout is None:
                    ok = False; break
                pv = self._get_prevout(prev_txid, prev_vout)
                if not pv:
                    ok = False; break
                prevouts.append(pv)
            if not ok:
                continue
            for e in self.tap.extract_edges(tx_json, raw_hex, prevouts, txid):
                self._add_edge(e)

    def collect_from_block_range(self, start_height: int, end_height: int):
        if not self.tap.enabled:
            print("Taproot disabled: pip install btclib coincurve", file=sys.stderr)
            return
        for h in range(start_height, end_height + 1):
            try:
                bh = self.rpc.getblockhash(h)
                blk = self.rpc.getblock(bh, 2)
            except Exception as e:
                print(f"RPC error at height {h}: {e}", file=sys.stderr)
                continue
            self.collect_from_txids([tx["txid"] for tx in blk.get("tx", [])])

    def collect_from_mempool(self):
        if not self.tap.enabled:
            print("Taproot disabled: pip install btclib coincurve", file=sys.stderr)
            return
        try:
            txids = self.rpc.getrawmempool()
        except Exception as e:
            print(f"RPC error getrawmempool: {e}", file=sys.stderr)
            return
        self.collect_from_txids(txids)

    # Detection

    def detect_duplicate_rq(self) -> List[LeakFinding]:
        findings = []
        for (r, q), edges in self.edges_by_rq.items():
            if len(edges) < 2:
                continue
            uniq = {(e.s, e.e, e.sighash_type) for e in edges}
            if len(uniq) >= 2:
                findings.append(LeakFinding(
                    kind="schnorr_duplicate_rq",
                    detail={"r_x": str(r), "pubkey_xonly": q, "count": len(edges),
                            "examples": [{"txid": e.txid, "vin": e.vin, "s": str(e.s), "e": str(e.e)} for e in edges[:6]]}
                ))
        return findings

    def _build_component_matrices(self):
        # Unknowns: [k_r for r] + [x_q for q]; eq: 1*k_r + e*x_q = s
        adj = defaultdict(list)
        edge_map = defaultdict(list)
        for e in self.edges:
            rn = ('r', e.r_x); qn = ('q', e.pubkey_xonly_hex)
            adj[rn].append(qn); adj[qn].append(rn)
            edge_map[(rn, qn)].append(e)

        visited, components = set(), []

        def bfs(start):
            comp = set(); dq = deque([start]); visited.add(start)
            while dq:
                u = dq.popleft(); comp.add(u)
                for v in adj[u]:
                    if v not in visited:
                        visited.add(v); dq.append(v)
            return comp

        for node in list(adj.keys()):
            if node in visited: continue
            comp_nodes = bfs(node)
            r_nodes = sorted([n for n in comp_nodes if n[0] == 'r'], key=lambda x: x[1])
            q_nodes = sorted([n for n in comp_nodes if n[0] == 'q'], key=lambda x: x[1])
            idx_r = {r_nodes[i]: i for i in range(len(r_nodes))}
            idx_q = {q_nodes[i]: i for i in range(len(q_nodes))}
            A, b, used = [], [], []
            for rn in r_nodes:
                for qn in adj[rn]:
                    if qn[0] != 'q': continue
                    for e in edge_map[(rn, qn)]:
                        row = [0] * (len(r_nodes) + len(q_nodes))
                        row[idx_r[rn]] = 1
                        row[len(r_nodes) + idx_q[qn]] = e.e % SECP256K1_N
                        A.append(row); b.append(e.s % SECP256K1_N); used.append(e)
            components.append((A, b, r_nodes, q_nodes, used))
        return components

    def _modular_rank(self, A: List[List[int]]) -> int:
        if not A: return 0
        m = [row[:] for row in A]
        rows, cols = len(m), len(m[0]); rank, col = 0, 0
        for r in range(rows):
            while col < cols and all(m[i][col] % SECP256K1_N == 0 for i in range(r, rows)):
                col += 1
            if col == cols: break
            pivot = None
            for i in range(r, rows):
                if m[i][col] % SECP256K1_N != 0:
                    pivot = i; break
            if pivot is None: col += 1; continue
            if pivot != r: m[r], m[pivot] = m[pivot], m[r]
            inv = modinv(m[r][col])
            m[r] = [(v * inv) % SECP256K1_N for v in m[r]]
            for i in range(rows):
                if i != r and m[i][col] != 0:
                    f = m[i][col] % SECP256K1_N
                    m[i] = [(m[i][j] - f * m[r][j]) % SECP256K1_N for j in range(cols)]
            rank += 1; col += 1
        return rank

    def detect_solvable_components(self) -> List[LeakFinding]:
        findings = []
        for A, b, r_nodes, q_nodes, used_edges in self._build_component_matrices():
            unknowns, eqs = len(r_nodes) + len(q_nodes), len(A)
            if unknowns == 0 or eqs < unknowns: continue
            if self._modular_rank(A) == unknowns:
                findings.append(LeakFinding(
                    kind="schnorr_solvable_component",
                    detail={
                        "unknowns": unknowns, "equations": eqs,
                        "r_nodes": [n[1] for n in r_nodes],
                        "q_nodes": [n[1] for n in q_nodes],
                        "sample_edges": [{"txid": e.txid, "vin": e.vin, "r_x": str(e.r_x), "s": str(e.s), "e": str(e.e), "pubkey_xonly": e.pubkey_xonly_hex} for e in used_edges[:10]],
                    }
                ))
        return findings

    def find_cycles(self, max_len: int = 8) -> List[list]:
        adj = defaultdict(list)
        for e in self.edges:
            rn = ('r', e.r_x); qn = ('q', e.pubkey_xonly_hex)
            adj[rn].append(qn); adj[qn].append(rn)

        cycles, seen = [], set()
        def dfs(path, target, depth_left):
            cur = path[-1]
            if depth_left == 0:
                if cur == target and len(path) >= 4 and len(path) % 2 == 0:
                    key = tuple(path)
                    if key not in seen:
                        seen.add(key); cycles.append(list(path))
                return
            for nxt in adj[cur]:
                if len(path) >= 2 and nxt == path[-2]: continue
                if nxt in path and nxt != target: continue
                if path[-1][0] == nxt[0]: continue
                dfs(path + [nxt], target, depth_left - 1)
        for r in sorted(self.unique_r):
            start = ('r', r)
            for L in range(4, max_len + 1, 2):
                dfs([start], start, L)
        return cycles

# ---------- Solvers (non-mainnet only) ----------

class ECDSASolver:
    def __init__(self, analyzer: ECDSANonceAnalyzer, chain: str):
        self.A = analyzer
        self.chain = chain
        if CC_PrivateKey is None:
            raise RuntimeError("coincurve not available. pip install coincurve")

    def _pub_from_priv(self, xpriv: int) -> str:
        return CC_PrivateKey(xpriv.to_bytes(32, 'big')).public_key.format(compressed=True).hex()

    def _solve_linear_system_mod(self, A: List[List[int]], b: List[int]) -> Optional[List[int]]:
        if not A:
            return None
        m = [row[:] + [b[i] % SECP256K1_N] for i, row in enumerate(A)]
        rows, cols = len(m), len(A[0])
        r = c = 0
        where = [-1] * cols
        while r < rows and c < cols:
            pivot = None
            for i in range(r, rows):
                if m[i][c] % SECP256K1_N != 0:
                    pivot = i; break
            if pivot is None:
                c += 1; continue
            m[r], m[pivot] = m[pivot], m[r]
            inv = modinv(m[r][c])
            for j in range(c, cols + 1):
                m[r][j] = (m[r][j] * inv) % SECP256K1_N
            for i in range(rows):
                if i != r and m[i][c] != 0:
                    f = m[i][c] % SECP256K1_N
                    for j in range(c, cols + 1):
                        m[i][j] = (m[i][j] - f * m[r][j]) % SECP256K1_N
            where[c] = r; r += 1; c += 1
        for i in range(rows):
            if all(m[i][j] % SECP256K1_N == 0 for j in range(cols)) and m[i][cols] % SECP256K1_N != 0:
                return None
        rank = sum(1 for w in where if w != -1)
        if rank < cols:
            return None
        x = [0] * cols
        for j in range(cols):
            if where[j] != -1:
                x[j] = m[where[j]][cols] % SECP256K1_N
        return x

    def _solve_cycle(self, cycle_nodes: List[Tuple[str, int]]) -> Tuple[Dict[str, int], Dict[int, int]]:
        # Build edge list along cycle
        edges = []
        for a, b in zip(cycle_nodes, cycle_nodes[1:]):
            if a[0] == 'r' and b[0] == 'q':
                r, q = a[1], b[1]
            elif a[0] == 'q' and b[0] == 'r':
                r, q = b[1], a[1]
            else:
                continue
            cand = self.A.edges_by_rq.get((r, q), [])
            if cand:
                edges.append(cand[0])
        if len(edges) < 2:
            return {}, {}

        r_nodes = sorted(list({('r', e.r) for e in edges}), key=lambda t: t[1])
        q_nodes = sorted(list({('q', e.pubkey_hex) for e in edges}), key=lambda t: t[1])
        ridx = {r_nodes[i]: i for i in range(len(r_nodes))}
        qidx = {q_nodes[i]: i for i in range(len(q_nodes))}
        E = len(edges)

        # brute-force s-sign flips
        for mask in range(1 << E):
            A_rows, b_vec = [], []
            for i, e in enumerate(edges):
                s_eff = e.s % SECP256K1_N
                if (mask >> i) & 1:
                    s_eff = (-s_eff) % SECP256K1_N
                row = [0] * (len(r_nodes) + len(q_nodes))
                row[ridx[('r', e.r)]] = s_eff
                row[len(r_nodes) + qidx[('q', e.pubkey_hex)]] = (-e.r) % SECP256K1_N
                A_rows.append(row)
                b_vec.append(e.z % SECP256K1_N)
            sol = self._solve_linear_system_mod(A_rows, b_vec)
            if sol is None:
                continue
            k_map = {}
            x_map = {}
            for i, rn in enumerate(r_nodes):
                kv = sol[i] % SECP256K1_N
                if kv == 0:
                    k_map = {}; break
                k_map[rn[1]] = kv
            if not k_map:
                continue
            for i, qn in enumerate(q_nodes):
                xv = sol[len(r_nodes) + i] % SECP256K1_N
                if not (1 <= xv < SECP256K1_N):
                    x_map = {}; break
                x_map[qn[1]] = xv
            if not x_map:
                continue
            # Verify derived pubkeys
            ok = True
            for qhex, xpriv in x_map.items():
                if self._pub_from_priv(xpriv).lower() != qhex.lower():
                    ok = False; break
            if ok:
                return x_map, k_map
        return {}, {}

    def _propagate(self, x_by_q: Dict[str, int], k_by_r: Dict[int, int]) -> Tuple[Dict[str, int], Dict[int, int]]:
        changed = True
        while changed:
            changed = False
            # If k_r known, solve x_q = (s*k - z) * r^{-1}
            for r, edges in list(self.A.edges_by_r.items()):
                if r not in k_by_r:
                    continue
                k = k_by_r[r]
                for e in edges:
                    if e.pubkey_hex in x_by_q:
                        continue
                    for s_eff in (e.s % SECP256K1_N, (-e.s) % SECP256K1_N):
                        x_cand = ((s_eff * k - e.z) % SECP256K1_N) * modinv(e.r % SECP256K1_N) % SECP256K1_N
                        if 1 <= x_cand < SECP256K1_N and self._pub_from_priv(x_cand).lower() == e.pubkey_hex.lower():
                            x_by_q[e.pubkey_hex] = x_cand
                            changed = True
                            break
            # If x_q known, try to deduce k_r if consistent across edges
            for q, edges in list(self.A.edges_by_q.items()):
                if q not in x_by_q:
                    continue
                xpriv = x_by_q[q]
                by_r = defaultdict(list)
                for e in edges:
                    by_r[e.r].append(e)
                for r, es in by_r.items():
                    if r in k_by_r:
                        continue
                    cand = set()
                    for e in es:
                        for s_eff in (e.s % SECP256K1_N, (-e.s) % SECP256K1_N):
                            denom = s_eff % SECP256K1_N
                            if denom == 0:
                                continue
                            k_val = ((e.z + (e.r % SECP256K1_N) * xpriv) % SECP256K1_N) * modinv(denom) % SECP256K1_N
                            cand.add(k_val)
                    if len(cand) == 1:
                        k_by_r[r] = next(iter(cand))
                        changed = True
        return x_by_q, k_by_r

    def derive(self, cycles: List[list], max_cycle_len: int) -> Tuple[Dict[str, int], Dict[int, int]]:
        if self.chain == 'main':
            print("ECDSA solver disabled on mainnet.", file=sys.stderr)
            return {}, {}
        x_by_q: Dict[str, int] = {}
        k_by_r: Dict[int, int] = {}

        # Closed-form duplicates
        for (r, q), edges in self.A.edges_by_rq.items():
            uniq = list({(e.z, e.s, e.sighash_type): e for e in edges}.values())
            if len(uniq) < 2:
                continue
            for i in range(len(uniq)):
                for j in range(i+1, len(uniq)):
                    e1, e2 = uniq[i], uniq[j]
                    for s1 in (e1.s % SECP256K1_N, (-e1.s) % SECP256K1_N):
                        for s2 in (e2.s % SECP256K1_N, (-e2.s) % SECP256K1_N):
                            denom = (s1 - s2) % SECP256K1_N
                            if denom == 0: continue
                            k = ((e1.z - e2.z) % SECP256K1_N) * modinv(denom) % SECP256K1_N
                            if k == 0: continue
                            xpriv = ((s1 * k - e1.z) % SECP256K1_N) * modinv(e1.r % SECP256K1_N) % SECP256K1_N
                            if 1 <= xpriv < SECP256K1_N and self._pub_from_priv(xpriv).lower() == q.lower():
                                x_by_q[q] = xpriv; k_by_r[r] = k

        # Cycle solving
        for cyc in cycles:
            x_map, k_map = self._solve_cycle(cyc)
            for q, x in x_map.items():
                x_by_q.setdefault(q, x)
            for r, k in k_map.items():
                k_by_r.setdefault(r, k)

        # Propagate
        x_by_q, k_by_r = self._propagate(x_by_q, k_by_r)
        return x_by_q, k_by_r

class SchnorrSolver:
    def __init__(self, analyzer: SchnorrNonceAnalyzer, chain: str):
        self.A = analyzer
        self.chain = chain
        if not HAS_COINCURVE:
            raise RuntimeError("coincurve not available. pip install coincurve")

    def _xonly_from_priv(self, xpriv: int) -> str:
        # 65-byte uncompressed: 0x04 || X(32) || Y(32); take X for xonly
        P = CC_PrivateKey(xpriv.to_bytes(32, 'big')).public_key.format(compressed=False)
        return P[1:33].hex()

    def _solve_linear_system_mod(self, A: List[List[int]], b: List[int]) -> Optional[List[int]]:
        if not A:
            return None
        m = [row[:] + [b[i] % SECP256K1_N] for i, row in enumerate(A)]
        rows, cols = len(m), len(A[0])
        r = c = 0
        where = [-1] * cols
        while r < rows and c < cols:
            pivot = None
            for i in range(r, rows):
                if m[i][c] % SECP256K1_N != 0:
                    pivot = i; break
            if pivot is None:
                c += 1; continue
            m[r], m[pivot] = m[pivot], m[r]
            inv = modinv(m[r][c])
            for j in range(c, cols + 1):
                m[r][j] = (m[r][j] * inv) % SECP256K1_N
            for i in range(rows):
                if i != r and m[i][c] != 0:
                    f = m[i][c] % SECP256K1_N
                    for j in range(c, cols + 1):
                        m[i][j] = (m[i][j] - f * m[r][j]) % SECP256K1_N
            where[c] = r; r += 1; c += 1
        for i in range(rows):
            if all(m[i][j] % SECP256K1_N == 0 for j in range(cols)) and m[i][cols] % SECP256K1_N != 0:
                return None
        rank = sum(1 for w in where if w != -1)
        if rank < cols:
            return None
        x = [0] * cols
        for j in range(cols):
            if where[j] != -1:
                x[j] = m[where[j]][cols] % SECP256K1_N
        return x

    def _propagate(self, x_by_q: Dict[str, int], k_by_r: Dict[int, int]) -> Tuple[Dict[str, int], Dict[int, int]]:
        changed = True
        while changed:
            changed = False
            # If x known and edge known, k = s - e*x
            for q, edges in list(self.A.edges_by_q.items()):
                if q not in x_by_q:
                    continue
                xpriv = x_by_q[q]
                for e in edges:
                    if e.r_x in k_by_r:
                        continue
                    k = (e.s - e.e * xpriv) % SECP256K1_N
                    if k != 0:
                        k_by_r[e.r_x] = k
                        changed = True
            # If k known, x = (s - k) * e^{-1}
            for r, edges in list(self.A.edges_by_r.items()):
                if r not in k_by_r:
                    continue
                k = k_by_r[r]
                for e in edges:
                    if e.pubkey_xonly_hex in x_by_q:
                        continue
                    if e.e == 0:
                        continue
                    xpriv = ((e.s - k) % SECP256K1_N) * modinv(e.e) % SECP256K1_N
                    if 1 <= xpriv < SECP256K1_N and self._xonly_from_priv(xpriv).lower() == e.pubkey_xonly_hex.lower():
                        x_by_q[e.pubkey_xonly_hex] = xpriv
                        changed = True
        return x_by_q, k_by_r

    def derive(self, cycles: List[list]) -> Tuple[Dict[str, int], Dict[int, int]]:
        if self.chain == 'main':
            print("Schnorr solver disabled on mainnet.", file=sys.stderr)
            return {}, {}
        x_by_q: Dict[str, int] = {}
        k_by_r: Dict[int, int] = {}

        # Duplicates: x = (s1 - s2) * (e1 - e2)^{-1}
        for (r, q), edges in self.A.edges_by_rq.items():
            uniq = list({(e.s, e.e, e.sighash_type): e for e in edges}.values())
            if len(uniq) < 2:
                continue
            for i in range(len(uniq)):
                for j in range(i+1, len(uniq)):
                    e1, e2 = uniq[i], uniq[j]
                    denom = (e1.e - e2.e) % SECP256K1_N
                    if denom == 0:
                        continue
                    xpriv = ((e1.s - e2.s) % SECP256K1_N) * modinv(denom) % SECP256K1_N
                    if 1 <= xpriv < SECP256K1_N and self._xonly_from_priv(xpriv).lower() == q.lower():
                        x_by_q[q] = xpriv
                        k = (e1.s - e1.e * xpriv) % SECP256K1_N
                        if k != 0:
                            k_by_r[r] = k

        # Cycles (no sign ambiguity)
        for cyc in cycles:
            edges = []
            for a, b in zip(cyc, cyc[1:]):
                if a[0] == 'r' and b[0] == 'q':
                    r, q = a[1], b[1]
                elif a[0] == 'q' and b[0] == 'r':
                    r, q = b[1], a[1]
                else:
                    continue
                cand = self.A.edges_by_rq.get((r, q), [])
                if cand:
                    edges.append(cand[0])
            if len(edges) < 2:
                continue
            r_nodes = sorted(list({('r', e.r_x) for e in edges}), key=lambda t: t[1])
            q_nodes = sorted(list({('q', e.pubkey_xonly_hex) for e in edges}), key=lambda t: t[1])
            ridx = {r_nodes[i]: i for i in range(len(r_nodes))}
            qidx = {q_nodes[i]: i for i in range(len(q_nodes))}
            A_rows, b_vec = [], []
            for e in edges:
                row = [0] * (len(r_nodes) + len(q_nodes))
                row[ridx[('r', e.r_x)]] = 1
                row[len(r_nodes) + qidx[('q', e.pubkey_xonly_hex)]] = e.e % SECP256K1_N
                A_rows.append(row); b_vec.append(e.s % SECP256K1_N)
            sol = self._solve_linear_system_mod(A_rows, b_vec)
            if sol is None:
                continue
            k_map, x_map = {}, {}
            for i, rn in enumerate(r_nodes):
                kv = sol[i] % SECP256K1_N
                if kv == 0:
                    k_map = {}; break
                k_map[rn[1]] = kv
            if not k_map:
                continue
            for i, qn in enumerate(q_nodes):
                xv = sol[len(r_nodes) + i] % SECP256K1_N
                if not (1 <= xv < SECP256K1_N):
                    x_map = {}; break
                x_map[qn[1]] = xv
            if not x_map:
                continue
            # Verify xonly pubkeys
            ok = True
            for qhex, xpriv in x_map.items():
                if self._xonly_from_priv(xpriv).lower() != qhex.lower():
                    ok = False; break
            if ok:
                for q, x in x_map.items():
                    x_by_q.setdefault(q, x)
                for r, k in k_map.items():
                    k_by_r.setdefault(r, k)

        # Propagate
        x_by_q, k_by_r = self._propagate(x_by_q, k_by_r)
        return x_by_q, k_by_r

# ---------- Graph export ----------

def export_graphml_ecdsa(an: ECDSANonceAnalyzer, path: str):
    r_nodes = {('r', r) for r in an.unique_r}
    q_nodes = {('q', q) for q in an.unique_q}
    node_ids, nodes_out = {}, []
    i = 0
    for n in sorted(r_nodes, key=lambda x: x[1]):
        node_ids[n] = f"n{i}"; i += 1
    for n in sorted(q_nodes, key=lambda x: x[1]):
        node_ids[n] = f"n{i}"; i += 1
    with open(path, "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n')
        f.write('  <graph edgedefault="undirected">\n')
        for n, nid in node_ids.items():
            f.write(f'    <node id="{nid}"><data key="type">{n[0]}</data><data key="label">{n[1]}</data></node>\n')
        ei = 0
        for e in an.edges:
            u = ('r', e.r); v = ('q', e.pubkey_hex)
            f.write(f'    <edge id="e{ei}" source="{node_ids[u]}" target="{node_ids[v]}"/>\n'); ei += 1
        f.write('  </graph>\n</graphml>\n')

def export_graphml_schnorr(an: SchnorrNonceAnalyzer, path: str):
    r_nodes = {('r', r) for r in an.unique_r}
    q_nodes = {('q', q) for q in an.unique_q}
    node_ids, nodes_out = {}, []
    i = 0
    for n in sorted(r_nodes, key=lambda x: x[1]):
        node_ids[n] = f"n{i}"; i += 1
    for n in sorted(q_nodes, key=lambda x: x[1]):
        node_ids[n] = f"n{i}"; i += 1
    with open(path, "w") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n')
        f.write('  <graph edgedefault="undirected">\n')
        for n, nid in node_ids.items():
            f.write(f'    <node id="{nid}"><data key="type">{n[0]}</data><data key="label">{n[1]}</data></node>\n')
        ei = 0
        for e in an.edges:
            u = ('r', e.r_x); v = ('q', e.pubkey_xonly_hex)
            f.write(f'    <edge id="e{ei}" source="{node_ids[u]}" target="{node_ids[v]}"/>\n'); ei += 1
        f.write('  </graph>\n</graphml>\n')

# ---------- CLI ----------

def load_txids_file(path: str) -> List[str]:
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip()]

def main():
    ap = argparse.ArgumentParser(description="ECDSA + Taproot (key-path) nonce graph detector/solver (Chainstack RPC)")
    ap.add_argument("--start", type=int, help="Start block height")
    ap.add_argument("--end", type=int, help="End block height")
    ap.add_argument("--mempool", action="store_true", help="Scan mempool")
    ap.add_argument("--txids-file", type=str, help="Txids file, one per line")
    ap.add_argument("--out-json", type=str, help="Write findings JSON")
    ap.add_argument("--out-csv-ecdsa", type=str, help="Write ECDSA edges CSV")
    ap.add_argument("--out-csv-taproot", type=str, help="Write Taproot edges CSV")
    ap.add_argument("--graphml-ecdsa", type=str, help="Export ECDSA graph as GraphML")
    ap.add_argument("--graphml-taproot", type=str, help="Export Taproot graph as GraphML")
    ap.add_argument("--solve", action="store_true", help="Attempt secret derivation (disabled on mainnet)")
    ap.add_argument("--out-secrets", type=str, help="Write recovered secrets JSON (testnet/regtest only)")
    ap.add_argument("--max-cycle-len", type=int, default=8, help="Max cycle length to search/solve")
    args = ap.parse_args()

    rpc_url = os.environ.get("RPC_URL")
    rpc_user = os.environ.get("RPC_USER")
    rpc_pass = os.environ.get("RPC_PASSWORD")
    if not rpc_url:
        print("Please set RPC_URL (and optionally RPC_USER, RPC_PASSWORD).", file=sys.stderr)
        sys.exit(1)

    rpc = BitcoinRPC(rpc_url, rpc_user, rpc_pass)
    chain = rpc.getblockchaininfo().get("chain", "main")
    print(f"Connected. Chain: {chain}")

    ecdsa = ECDSANonceAnalyzer(rpc, max_cycle_length=args.max_cycle_len)
    tap = SchnorrNonceAnalyzer(rpc, max_cycle_length=args.max_cycle_len)

    # Collect
    if args.txids_file:
        txids = load_txids_file(args.txids_file)
        ecdsa.collect_from_txids(txids)
        tap.collect_from_txids(txids)
    elif args.mempool:
        ecdsa.collect_from_mempool()
        tap.collect_from_mempool()
    elif args.start is not None and args.end is not None:
        ecdsa.collect_from_block_range(args.start, args.end)
        tap.collect_from_block_range(args.start, args.end)
    else:
        print("Provide --txids-file, --mempool, or --start and --end.", file=sys.stderr)
        sys.exit(1)

    # Stats
    print(f"ECDSA: signatures={len(ecdsa.edges)} r={len(ecdsa.unique_r)} pubkeys={len(ecdsa.unique_q)}")
    print(f"Taproot: signatures={len(tap.edges)} r_x={len(tap.unique_r)} xonly_pubkeys={len(tap.unique_q)}")

    # Detection
    findings = []
    e_dup = ecdsa.detect_duplicate_rq()
    e_solv = ecdsa.detect_solvable_components()
    e_cyc = ecdsa.find_cycles(args.max_cycle_len)
    print(f"ECDSA duplicates: {len(e_dup)} | solvable comps: {len(e_solv)} | cycles: {len(e_cyc)}")

    s_dup = tap.detect_duplicate_rq()
    s_solv = tap.detect_solvable_components()
    s_cyc = tap.find_cycles(args.max_cycle_len)
    print(f"Taproot duplicates: {len(s_dup)} | solvable comps: {len(s_solv)} | cycles: {len(s_cyc)}")

    findings.extend([{"kind": f.kind, "detail": f.detail} for f in (e_dup + e_solv + s_dup + s_solv)])

    if args.out_json:
        with open(args.out_json, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"Wrote findings to {args.out_json}")

    # CSV exports
    if args.out_csv_ecdsa:
        import csv
        with open(args.out_csv_ecdsa, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["txid", "vin", "pubkey", "r", "s", "z", "sighash_type", "is_witness", "script_type"])
            for e in ecdsa.edges:
                w.writerow([e.txid, e.vin, e.pubkey_hex, e.r, e.s, e.z, e.sighash_type, int(e.is_witness), e.script_type])
        print(f"Wrote ECDSA CSV: {args.out_csv_ecdsa}")

    if args.out_csv_taproot:
        import csv
        with open(args.out_csv_taproot, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["txid", "vin", "xonly_pubkey", "r_x", "s", "e", "sighash_type", "script_type"])
            for e in tap.edges:
                w.writerow([e.txid, e.vin, e.pubkey_xonly_hex, e.r_x, e.s, e.e, e.sighash_type, e.script_type])
        print(f"Wrote Taproot CSV: {args.out_csv_taproot}")

    # GraphML
    if args.graphml_ecdsa:
        export_graphml_ecdsa(ecdsa, args.graphml_ecdsa)
        print(f"Exported ECDSA GraphML: {args.graphml_ecdsa}")
    if args.graphml_taproot:
        export_graphml_schnorr(tap, args.graphml_taproot)
        print(f"Exported Taproot GraphML: {args.graphml_taproot}")

    # Solvers (non-mainnet)
    if args.solve:
        secrets = {"network": chain, "ecdsa": {"keys": [], "nonces": []}, "taproot": {"keys": [], "nonces": []}}
        if chain == 'main':
            print("Refusing to derive secrets on mainnet. Use testnet/regtest.", file=sys.stderr)
        else:
            # ECDSA
            try:
                e_solver = ECDSASolver(ecdsa, chain)
                x_by_q_e, k_by_r_e = e_solver.derive(e_cyc, args.max_cycle_len)
                print(f"ECDSA recovered: keys={len(x_by_q_e)} nonces={len(k_by_r_e)}")
                secrets["ecdsa"]["keys"] = [{"pubkey": q, "priv_hex": f"{x:064x}", "wif": privkey_to_wif(x, compressed=True, testnet=(chain != 'main'))} for q, x in x_by_q_e.items()]
                secrets["ecdsa"]["nonces"] = [{"r": str(r), "k": f"{k:064x}"} for r, k in k_by_r_e.items()]
            except Exception as ex:
                print(f"ECDSA solver error: {ex}", file=sys.stderr)

            # Taproot
            try:
                s_solver = SchnorrSolver(tap, chain)
                x_by_q_s, k_by_r_s = s_solver.derive(s_cyc)
                print(f"Taproot recovered: keys={len(x_by_q_s)} nonces={len(k_by_r_s)}")
                secrets["taproot"]["keys"] = [{"xonly_pubkey": q, "priv_hex": f"{x:064x}"} for q, x in x_by_q_s.items()]
                secrets["taproot"]["nonces"] = [{"r_x": str(r), "k": f"{k:064x}"} for r, k in k_by_r_s.items()]
            except Exception as ex:
                print(f"Taproot solver error: {ex}", file=sys.stderr)

        if args.out_secrets and chain != 'main':
            with open(args.out_secrets, "w") as f:
                json.dump(secrets, f, indent=2)
            print(f"Wrote secrets to {args.out_secrets}")

if __name__ == "__main__":
    main()
