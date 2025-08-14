#!/usr/bin/env python3
"""
working_scanner.py - Fixed version that properly parses blockchain.info data
"""

import json
import requests
import time
import os
from collections import defaultdict
from typing import List, Dict, Tuple, Optional
import argparse

try:
    from tqdm import tqdm
    HAS_TQDM = True
except:
    HAS_TQDM = False

class WorkingScanner:
    def __init__(self):
        self.session = requests.Session()
        self.r_values = defaultdict(list)
        self.total_sigs = 0
        self.total_txs = 0
        
    def parse_witness_stack(self, witness_hex: str) -> List[str]:
        """Parse witness data into individual stack items."""
        if not witness_hex or len(witness_hex) < 2:
            return []
        
        items = []
        i = 0
        
        try:
            # First byte is number of items
            num_items = int(witness_hex[i:i+2], 16)
            i += 2
            
            for _ in range(num_items):
                if i >= len(witness_hex):
                    break
                    
                # Get length of this item
                item_len = int(witness_hex[i:i+2], 16)
                i += 2
                
                # Extract the item
                if i + (item_len * 2) <= len(witness_hex):
                    item = witness_hex[i:i+(item_len * 2)]
                    items.append(item)
                    i += item_len * 2
                else:
                    break
                    
        except:
            pass
            
        return items
    
    def extract_signature_from_witness(self, witness_hex: str) -> Optional[Dict]:
        """Extract signature and pubkey from witness data."""
        items = self.parse_witness_stack(witness_hex)
        
        # P2WPKH has exactly 2 items: signature and pubkey
        if len(items) == 2:
            sig_hex = items[0]
            pubkey_hex = items[1]
            
            # Validate signature (DER format starts with 30)
            if len(sig_hex) >= 140 and sig_hex[:2] == '30':
                try:
                    # Extract R value from DER signature
                    # DER: 30 [total-len] 02 [r-len] [r-value] 02 [s-len] [s-value] [sighash]
                    if sig_hex[4:6] == '02':  # INTEGER tag for R
                        r_len = int(sig_hex[6:8], 16)
                        if 31 <= r_len <= 33:  # Valid R length
                            r_hex = sig_hex[8:8+(r_len*2)]
                            
                            # Validate pubkey (33 bytes compressed or 65 uncompressed)
                            if len(pubkey_hex) in [66, 130]:
                                return {
                                    'r': r_hex,
                                    'pubkey': pubkey_hex,
                                    'full_sig': sig_hex,
                                    'type': 'p2wpkh'
                                }
                except:
                    pass
        
        # P2TR has 1 or more items, first is Schnorr signature
        elif len(items) >= 1:
            sig_hex = items[0]
            # Schnorr signatures are 64 or 65 bytes
            if len(sig_hex) in [128, 130]:
                r_hex = sig_hex[:64]  # First 32 bytes is R
                return {
                    'r': r_hex,
                    'pubkey': 'p2tr',  # We'd need the output script to get the actual pubkey
                    'full_sig': sig_hex,
                    'type': 'p2tr'
                }
        
        return None
    
    def extract_signature_from_script(self, script_hex: str) -> Optional[Dict]:
        """Extract signature from legacy P2PKH scriptSig."""
        if not script_hex or len(script_hex) < 140:
            return None
        
        try:
            i = 0
            # First should be signature push
            if i < len(script_hex):
                sig_len = int(script_hex[i:i+2], 16)
                i += 2
                
                if sig_len > 0 and i + (sig_len * 2) <= len(script_hex):
                    sig_hex = script_hex[i:i+(sig_len * 2)]
                    i += sig_len * 2
                    
                    # Next should be pubkey push
                    if i < len(script_hex):
                        pub_len = int(script_hex[i:i+2], 16)
                        i += 2
                        
                        if pub_len > 0 and i + (pub_len * 2) <= len(script_hex):
                            pubkey_hex = script_hex[i:i+(pub_len * 2)]
                            
                            # Validate signature
                            if len(sig_hex) >= 140 and sig_hex[:2] == '30':
                                # Extract R value
                                if sig_hex[4:6] == '02':
                                    r_len = int(sig_hex[6:8], 16)
                                    if 31 <= r_len <= 33:
                                        r_hex = sig_hex[8:8+(r_len*2)]
                                        
                                        return {
                                            'r': r_hex,
                                            'pubkey': pubkey_hex,
                                            'full_sig': sig_hex,
                                            'type': 'p2pkh'
                                        }
        except:
            pass
        
        return None
    
    def scan_block(self, height: int) -> int:
        """Scan a block for signatures."""
        try:
            # Get block data
            resp = self.session.get(
                f"https://blockchain.info/block-height/{height}?format=json",
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
            
            if not data.get('blocks'):
                return 0
            
            block = data['blocks'][0]
            sigs_found = 0
            
            # Process each transaction
            for tx in block.get('tx', []):
                txid = tx.get('hash', '')
                self.total_txs += 1
                
                # Check each input
                for vin_idx, inp in enumerate(tx.get('inputs', [])):
                    # Skip coinbase
                    if not inp.get('prev_out') or inp.get('prev_out', {}).get('n') == 4294967295:
                        continue
                    
                    sig_data = None
                    
                    # Try to extract from witness
                    witness = inp.get('witness', '')
                    if witness and witness != '':
                        sig_data = self.extract_signature_from_witness(witness)
                    
                    # Try to extract from scriptSig if no witness
                    if not sig_data:
                        script = inp.get('script', '')
                        if script and script != '':
                            sig_data = self.extract_signature_from_script(script)
                    
                    # Store the signature data
                    if sig_data:
                        self.r_values[sig_data['r']].append({
                            'txid': txid,
                            'vin': vin_idx,
                            'height': height,
                            'pubkey': sig_data['pubkey'],
                            'type': sig_data['type'],
                            'full_sig': sig_data['full_sig'][:20] + '...'  # Truncate for display
                        })
                        sigs_found += 1
                        self.total_sigs += 1
            
            return sigs_found
            
        except Exception as e:
            print(f"Error scanning block {height}: {e}")
            return 0
    
    def scan_range(self, start: int, end: int):
        """Scan a range of blocks."""
        if HAS_TQDM:
            pbar = tqdm(range(start, end + 1), desc="Scanning blocks")
        else:
            pbar = range(start, end + 1)
        
        for height in pbar:
            sigs = self.scan_block(height)
            
            # Count reuse
            reuse_count = sum(1 for r, uses in self.r_values.items() if len(uses) > 1)
            
            if HAS_TQDM:
                pbar.set_postfix({
                    'sigs': self.total_sigs,
                    'unique_r': len(self.r_values),
                    'reuse': reuse_count
                })
            else:
                if height % 10 == 0:
                    print(f"Block {height}: {self.total_sigs} signatures, {reuse_count} reused R-values")
            
            time.sleep(0.05)  # Small delay to be nice to API
    
    def find_exploitable_reuse(self):
        """Find R-value reuse that could be exploitable."""
        exploitable = []
        
        for r_hex, uses in self.r_values.items():
            if len(uses) < 2:
                continue
            
            # Group by pubkey to find same-key reuse
            by_pubkey = defaultdict(list)
            for use in uses:
                by_pubkey[use['pubkey']].append(use)
            
            # Check each pubkey group
            for pubkey, pubkey_uses in by_pubkey.items():
                if len(pubkey_uses) > 1 and pubkey != 'p2tr':  # Skip P2TR for now
                    exploitable.append({
                        'r_value': r_hex,
                        'pubkey': pubkey,
                        'reuse_count': len(pubkey_uses),
                        'transactions': [u['txid'] for u in pubkey_uses],
                        'blocks': list(set(u['height'] for u in pubkey_uses))
                    })
        
        return exploitable
    
    def print_results(self):
        """Print scan results."""
        print("\n" + "="*60)
        print("SCAN RESULTS")
        print("="*60)
        print(f"Total transactions processed: {self.total_txs:,}")
        print(f"Total signatures found: {self.total_sigs:,}")
        print(f"Unique R-values: {len(self.r_values):,}")
        
        # Check for any reuse
        reused = [(r, uses) for r, uses in self.r_values.items() if len(uses) > 1]
        if reused:
            print(f"\n{'='*60}")
            print(f"R-VALUE REUSE FOUND: {len(reused)} cases")
            print(f"{'='*60}")
            
            for r_hex, uses in reused[:5]:  # Show first 5
                print(f"\nR-value: {r_hex[:32]}...")
                print(f"Used {len(uses)} times:")
                for use in uses[:3]:  # Show first 3 uses
                    print(f"  - Block {use['height']}, TX: {use['txid'][:16]}..., type: {use['type']}")
        
        # Check for exploitable reuse
        exploitable = self.find_exploitable_reuse()
        if exploitable:
            print(f"\n{'='*60}")
            print(f"⚠️  POTENTIALLY EXPLOITABLE REUSE: {len(exploitable)} cases")
            print(f"{'='*60}")
            
            for case in exploitable[:3]:  # Show first 3
                print(f"\nSAME KEY REUSED R-VALUE!")
                print(f"Pubkey: {case['pubkey'][:32]}...")
                print(f"R-value: {case['r_value'][:32]}...")
                print(f"Reused in {case['reuse_count']} transactions")
                print(f"Blocks: {case['blocks']}")
            
            # Save results
            with open("exploitable_reuse.json", "w") as f:
                json.dump(exploitable, f, indent=2)
            print(f"\nFull results saved to exploitable_reuse.json")

def main():
    parser = argparse.ArgumentParser(description="Working Bitcoin signature scanner")
    parser.add_argument("--start", type=int, required=True, help="Start block height")
    parser.add_argument("--end", type=int, required=True, help="End block height")
    args = parser.parse_args()
    
    print("="*60)
    print("BITCOIN SIGNATURE SCANNER")
    print("="*60)
    print(f"Scanning blocks {args.start} to {args.end}")
    
    scanner = WorkingScanner()
    
    start_time = time.time()
    scanner.scan_range(args.start, args.end)
    elapsed = time.time() - start_time
    
    scanner.print_results()
    
    print(f"\n{'='*60}")
    print(f"Completed in {elapsed:.2f} seconds")
    print(f"Speed: {(args.end - args.start + 1)/elapsed:.2f} blocks/sec")
    if scanner.total_sigs > 0:
        print(f"       {scanner.total_sigs/elapsed:.2f} signatures/sec")

if __name__ == "__main__":
    main()