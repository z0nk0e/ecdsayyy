import os
import re
import hashlib
import base58
import ecdsa
import requests
import time
import random
import google.generativeai as genai
from typing import List, Dict, Tuple

# ----------------------------------
# Flags and runtime configuration
# ----------------------------------
DEBUG = False            # Set True to print WIFs (not recommended)
TESTNET = False          # Set True to use Bitcoin testnet
REQUEST_TIMEOUT = 10     # Seconds for HTTP timeouts
HEADERS = {"User-Agent": "PhraseToBTC/1.0"}

# ----------------------------------
# Configuration (kept intact, now with env overrides)
# ----------------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or "YOUR_GEMINI_API_KEY"
CHAINSTACK_ENDPOINT = os.getenv("CHAINSTACK_ENDPOINT") or "YOUR_CHAINSTACK_ENDPOINT"  # Optional: Your Chainstack node endpoint
BLOCK_EXPLORER_API = "https://blockchain.info/balance?active="  # Fallback for mainnet

GEMINI_MODEL = os.getenv("GEMINI_MODEL") or "gemini-2.0-flash"  # Override with env if desired

# Initialize Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel(GEMINI_MODEL)

# Curve order for secp256k1
SECP256K1_N = ecdsa.SECP256k1.order

def generate_content(prompt: str) -> str:
    """Generate content using Gemini API."""
    try:
        response = model.generate_content(prompt)
        text = getattr(response, "text", None)
        return text or ""
    except Exception as e:
        print(f"Error generating content: {e}")
        return ""

def generate_phrases() -> List[str]:
    """Generate various phrases using Gemini, cleaned and de-duplicated."""
    prompts = [
        "Generate a list of 10 unique phrases related to Bitcoin, each phrase should be 5-10 words long.",
        "Create 10 unique phrases that could be used as Bitcoin wallet seed phrases, each phrase should be 5-10 words long.",
        "List 10 unique phrases that are suitable for Bitcoin wallet generation, each phrase should be 5-10 words long.",
        "Generate 10 unique Bitcoin-related phrases, each phrase should be between 5 and 10 words."
    ]
    
    all_phrases = []
    for prompt in prompts:
        content = generate_content(prompt)
        # Split, strip, and remove numbering/bullets
        lines = [ln.strip() for ln in content.split('\n') if ln.strip()]
        cleaned = []
        for ln in lines:
            # Remove bullets like "1. ", "1) ", "- ", "* ", "• " etc.
            ln = re.sub(r'^\s*(?:[\-\*\u2022]\s+|\d+[.)]\s+)', '', ln).strip()
            if ln:
                cleaned.append(ln)
        all_phrases.extend(cleaned)
        time.sleep(1)  # Rate limiting
    
    # De-duplicate while preserving order
    seen = set()
    unique_phrases = []
    for p in all_phrases:
        if p not in seen:
            seen.add(p)
            unique_phrases.append(p)
    return unique_phrases

def sha256(data: str) -> bytes:
    """Compute SHA-256 hash of input data."""
    return hashlib.sha256(data.encode()).digest()

def _digest_to_privkey(digest: bytes) -> bytes:
    """Map a digest into a valid secp256k1 private key [1, n-1]."""
    num = int.from_bytes(digest[:32], "big")
    num = (num % (SECP256K1_N - 1)) + 1
    return num.to_bytes(32, "big")

def hash_to_wif(phrase_hash: bytes, compressed: bool = True) -> str:
    """Convert hash to Wallet Import Format (WIF), with correct compression flag."""
    version = b'\xef' if TESTNET else b'\x80'
    priv = _digest_to_privkey(phrase_hash)
    payload = version + priv + (b'\x01' if compressed else b'')
    try:
        wif = base58.b58encode_check(payload)
    except Exception:
        # Manual Base58Check (fallback)
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        wif = base58.b58encode(payload + checksum)
    return wif.decode()

def wif_to_private_key(wif: str) -> bytes:
    """Convert WIF to private key (handles compressed/uncompressed)."""
    try:
        decoded = base58.b58decode_check(wif)
    except Exception:
        decoded = base58.b58decode(wif)
        decoded = decoded[:-4]  # remove checksum if not using _check
    body = decoded[1:]  # remove version
    if len(body) == 33 and body[-1] == 0x01:
        return body[:-1]  # compressed
    if len(body) == 32:
        return body  # uncompressed
    # Fallback: truncate to 32 bytes
    return body[:32]

def private_key_to_public_key(private_key: bytes) -> bytes:
    """Convert private key to compressed public key."""
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x.to_bytes(32, 'big')

def public_key_to_address(public_key: bytes) -> str:
    """Convert public key to P2PKH Bitcoin address (mainnet/testnet)."""
    sha = hashlib.sha256(public_key).digest()
    ripe = hashlib.new('ripemd160', sha).digest()
    version = b'\x6f' if TESTNET else b'\x00'
    extended = version + ripe
    try:
        address = base58.b58encode_check(extended)
        return address.decode()
    except Exception:
        checksum = hashlib.sha256(hashlib.sha256(extended).digest()).digest()[:4]
        address = base58.b58encode(extended + checksum)
        return address.decode()

def check_balance(address: str) -> Dict:
    """Check balance of a Bitcoin address using Blockstream API (fallback to blockchain.info on mainnet)."""
    base_url = "https://blockstream.info/testnet/api/address" if TESTNET else "https://blockstream.info/api/address"
    url = f"{base_url}/{address}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        cs = data.get("chain_stats", {})
        ms = data.get("mempool_stats", {})
        balance = cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)
        n_tx = cs.get("tx_count", 0) + ms.get("tx_count", 0)
        return {"final_balance": balance, "n_tx": n_tx}
    except requests.RequestException as e:
        print(f"Error checking balance via Blockstream: {e}")
        # Fallback only for mainnet
        if not TESTNET:
            try:
                url2 = f"{BLOCK_EXPLORER_API}{address}"
                r2 = requests.get(url2, headers=HEADERS, timeout=REQUEST_TIMEOUT)
                if r2.status_code == 200:
                    data2 = r2.json()
                    return data2.get(address, {})
                else:
                    print(f"Fallback explorer HTTP {r2.status_code}")
            except Exception as e2:
                print(f"Fallback explorer error: {e2}")
        return {}

def process_phrase(phrase: str) -> Tuple[str, Dict]:
    """Process a single phrase through the entire pipeline."""
    print(f"\nProcessing phrase: {phrase}")
    
    # Step 1: Hash the phrase
    phrase_hash = sha256(phrase)
    
    # Step 2: Convert to WIF (compressed)
    wif = hash_to_wif(phrase_hash, compressed=True)
    if DEBUG:
        print(f"WIF: {wif}")
    
    # Step 3: Get private key
    private_key = wif_to_private_key(wif)
    
    # Step 4: Generate public key (compressed)
    public_key = private_key_to_public_key(private_key)
    
    # Step 5: Generate address
    address = public_key_to_address(public_key)
    print(f"Address: {address}")
    
    # Step 6: Check balance
    balance_info = check_balance(address)
    print(f"Balance info: {balance_info}")
    
    return address, balance_info

def main():
    print("Starting phrase generation and address checking...")
    
    # Generate phrases
    phrases = generate_phrases()
    print(f"\nGenerated {len(phrases)} phrases:")
    for i, phrase in enumerate(phrases, 1):
        print(f"{i}. {phrase}")
    
    # Process each phrase
    results = []
    for phrase in phrases:
        address, balance_info = process_phrase(phrase)
        results.append({
            "phrase": phrase,
            "address": address,
            "balance": balance_info.get('final_balance', 0),
            "transactions": balance_info.get('n_tx', 0)
        })
        time.sleep(1)  # Rate limiting for API calls
    
    # Filter addresses with balance
    funded_addresses = [r for r in results if r['balance'] > 0]
    
    # Print summary
    print("\n=== Summary ===")
    print(f"Total phrases processed: {len(results)}")
    print(f"Addresses with balance: {len(funded_addresses)}")
    
    if funded_addresses:
        print("\nFunded addresses found:")
        for addr in funded_addresses:
            print(f"\nPhrase: {addr['phrase']}")
            print(f"Address: {addr['address']}")
            print(f"Balance: {addr['balance']} satoshis")
            print(f"Transactions: {addr['transactions']}")

if __name__ == "__main__":
    main()