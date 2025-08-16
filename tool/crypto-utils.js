// crypto-utils.js - Complete implementation
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import ECPairFactory from 'ecpair';
import { Buffer } from 'buffer';
import crypto from 'crypto';

// Initialize ECPair with tiny-secp256k1
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

// Constants
export const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

// Modular inverse using extended Euclidean algorithm
export function modInv(a, n = SECP256K1_N) {
  a = ((a % n) + n) % n;
  
  let t = 0n;
  let newT = 1n;
  let r = n;
  let newR = a;
  
  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }
  
  if (r > 1n) throw new Error('a is not invertible');
  if (t < 0n) t = t + n;
  
  return t;
}

// Convert bytes to BigInt
export function bytesToBigInt(bytes) {
  const hex = Buffer.from(bytes).toString('hex');
  return BigInt('0x' + (hex || '0'));
}

// Convert BigInt to bytes (32 bytes for secp256k1)
export function bigIntToBytes(num, length = 32) {
  const hex = num.toString(16).padStart(length * 2, '0');
  return Buffer.from(hex, 'hex');
}

// SHA256 hash
export function sha256(data) {
  return crypto.createHash('sha256').update(Buffer.from(data)).digest();
}

// Double SHA256
export function hash256(data) {
  return sha256(sha256(data));
}

// RIPEMD160 hash
export function ripemd160(data) {
  return crypto.createHash('ripemd160').update(Buffer.from(data)).digest();
}

// Hash160 (SHA256 then RIPEMD160)
export function hash160(data) {
  return ripemd160(sha256(data));
}

// Tagged hash for Taproot (BIP340)
export function taggedHash(tag, data) {
  const tagHash = sha256(Buffer.from(tag, 'utf8'));
  return sha256(Buffer.concat([tagHash, tagHash, Buffer.from(data)]));
}

// Parse DER signature
export function parseDerSignature(derSig) {
  const sig = bitcoin.script.signature.decode(Buffer.from(derSig));
  return {
    r: bytesToBigInt(sig.signature.slice(0, 32)),
    s: bytesToBigInt(sig.signature.slice(32, 64)),
    hashType: sig.hashType
  };
}

// Check if script is P2PKH
export function isP2PKH(script) {
  try {
    bitcoin.payments.p2pkh({ output: script });
    return true;
  } catch {
    return false;
  }
}

// Check if script is P2WPKH
export function isP2WPKH(script) {
  try {
    bitcoin.payments.p2wpkh({ output: script });
    return true;
  } catch {
    return false;
  }
}

// Check if script is P2TR (Taproot)
export function isP2TR(script) {
  try {
    bitcoin.payments.p2tr({ output: script });
    return true;
  } catch {
    return false;
  } 
}

// Extract public key from P2PKH scriptSig
export function extractPubkeyFromScriptSig(scriptSig) {
  const chunks = bitcoin.script.decompile(scriptSig);
  if (chunks && chunks.length >= 2) {
    const lastChunk = chunks[chunks.length - 1];
    if (Buffer.isBuffer(lastChunk) && (lastChunk.length === 33 || lastChunk.length === 65)) {
      return lastChunk;
    }
  }
  return null;
}

// Extract signature from P2PKH scriptSig
export function extractSigFromScriptSig(scriptSig) {
  const chunks = bitcoin.script.decompile(scriptSig);
  if (chunks && chunks.length >= 1) {
    const firstChunk = chunks[0];
    if (Buffer.isBuffer(firstChunk)) {
      return firstChunk;
    }
  }
  return null;
}