// signature-extractors.js - Complete extraction logic
import * as bitcoin from 'bitcoinjs-lib';
import { Buffer } from 'buffer';
import { 
  bytesToBigInt, 
  parseDerSignature,
  extractPubkeyFromScriptSig,
  extractSigFromScriptSig,
  taggedHash,
  SECP256K1_N
} from './crypto-utils';

export class SignatureExtractor {
  constructor(network = bitcoin.networks.bitcoin) {
    this.network = network;
  }

  // Extract ECDSA signatures from transaction
  extractECDSASignatures(tx, vin, prevout) {
    const signatures = [];
    
    // Handle P2PKH
    if (vin.scriptSig && vin.scriptSig.hex) {
      const scriptSig = Buffer.from(vin.scriptSig.hex, 'hex');
      const sig = extractSigFromScriptSig(scriptSig);
      const pubkey = extractPubkeyFromScriptSig(scriptSig);
      
      if (sig && pubkey) {
        try {
          const parsed = parseDerSignature(sig);
          const z = this.computeSignatureHash(tx, vin.vout, parsed.hashType, prevout, false);
          
          signatures.push({
            r: parsed.r,
            s: parsed.s,
            z: bytesToBigInt(z) % SECP256K1_N,
            hashType: parsed.hashType,
            pubkey: pubkey.toString('hex'),
            isWitness: false,
            scriptType: 'p2pkh'
          });
        } catch (error) {
          // Invalid signature format, skip
        }
      }
    }
    
    // Handle P2WPKH (native segwit)
    if (vin.txinwitness && vin.txinwitness.length >= 2) {
      try {
        const witnessSig = Buffer.from(vin.txinwitness[0], 'hex');
        const witnessPubkey = Buffer.from(vin.txinwitness[1], 'hex');
        
        if (witnessSig.length > 0 && (witnessPubkey.length === 33 || witnessPubkey.length === 65)) {
          const parsed = parseDerSignature(witnessSig);
          const z = this.computeSignatureHash(tx, vin.vout, parsed.hashType, prevout, true);
          
          signatures.push({
            r: parsed.r,
            s: parsed.s,
            z: bytesToBigInt(z) % SECP256K1_N,
            hashType: parsed.hashType,
            pubkey: witnessPubkey.toString('hex'),
            isWitness: true,
            scriptType: 'p2wpkh'
          });
        }
      } catch (error) {
        // Invalid witness format, skip
      }
    }
    
    return signatures;
  }

  // Extract Schnorr signatures from Taproot transactions
  extractSchnorrSignatures(tx, vin, prevout) {
    const signatures = [];
    
    // Check if this is a P2TR output
    if (!prevout || !prevout.scriptPubKey || !prevout.scriptPubKey.hex) {
      return signatures;
    }
    
    const scriptPubKey = Buffer.from(prevout.scriptPubKey.hex, 'hex');
    
    // P2TR outputs are 34 bytes: OP_1 (0x51) + 32 byte x-only pubkey
    if (scriptPubKey.length !== 34 || scriptPubKey[0] !== 0x51 || scriptPubKey[1] !== 0x20) {
      return signatures;
    }
    
    // Check for key path spending (single item in witness)
    if (vin.txinwitness && vin.txinwitness.length >= 1) {
      const witnessItem = Buffer.from(vin.txinwitness[0], 'hex');
      
      // Schnorr signatures are 64 or 65 bytes (with sighash flag)
      if (witnessItem.length === 64 || witnessItem.length === 65) {
        const sigBytes = witnessItem.slice(0, 64);
        const sighashType = witnessItem.length === 65 ? witnessItem[64] : 0x00;
        
        // Extract x-only public key from output
        const pubkeyXOnly = scriptPubKey.slice(2, 34);
        
        // Compute the signature hash for Taproot
        const sigHash = this.computeTaprootSignatureHash(tx, vin.vout, sighashType, [prevout]);
        
        // Compute challenge e = H_tag(r || P || m)
        const r = sigBytes.slice(0, 32);
        const s = sigBytes.slice(32, 64);
        const e = taggedHash('BIP0340/challenge', Buffer.concat([r, pubkeyXOnly, sigHash]));
        
        signatures.push({
          r_x: bytesToBigInt(r),
          s: bytesToBigInt(s),
          e: bytesToBigInt(e) % SECP256K1_N,
          hashType: sighashType,
          pubkeyXOnly: pubkeyXOnly.toString('hex'),
          scriptType: 'p2tr-keypath'
        });
      }
    }
    
    return signatures;
  }

  // Compute signature hash for legacy/segwit transactions
  computeSignatureHash(tx, inputIndex, hashType, prevout, isWitness) {
    const txBuffer = Buffer.from(tx.hex, 'hex');
    const transaction = bitcoin.Transaction.fromHex(tx.hex);
    
    if (isWitness) {
      // For witness transactions, we need the amount
      const amount = Math.round(prevout.value * 100000000);
      const scriptCode = bitcoin.payments.p2pkh({ 
        hash: bitcoin.crypto.hash160(Buffer.from(prevout.scriptPubKey.hex, 'hex'))
      }).output;
      
      return transaction.hashForWitnessV0(inputIndex, scriptCode, amount, hashType);
    } else {
      // For legacy transactions
      const prevOutScript = Buffer.from(prevout.scriptPubKey.hex, 'hex');
      return transaction.hashForSignature(inputIndex, prevOutScript, hashType);
    }
  }

  // Compute signature hash for Taproot transactions (BIP341)
  computeTaprootSignatureHash(tx, inputIndex, hashType, prevouts) {
    const transaction = bitcoin.Transaction.fromHex(tx.hex);
    
    // Prepare spent outputs for sighash calculation
    const spentOutputs = prevouts.map(prevout => ({
      value: Math.round(prevout.value * 100000000),
      script: Buffer.from(prevout.scriptPubKey.hex, 'hex')
    }));
    
    // Compute Taproot sighash (simplified - full implementation would need all annex handling)
    const sigHashType = hashType || 0x00;
    
    // This is a simplified version - full BIP341 implementation would be more complex
    let hashPrevouts = Buffer.alloc(32);
    let hashAmounts = Buffer.alloc(32);
    let hashScriptPubkeys = Buffer.alloc(32);
    let hashSequences = Buffer.alloc(32);
    let hashOutputs = Buffer.alloc(32);
    
    // Compute hashes based on sighash type
    if ((sigHashType & 0x80) !== 0x80) { // SIGHASH_ANYONECANPAY not set
      const prevoutsConcat = Buffer.concat(transaction.ins.map(input => 
        Buffer.concat([input.hash, Buffer.from(input.index.toString(16).padStart(8, '0'), 'hex')])
      ));
      hashPrevouts = taggedHash('TapPrevouts', prevoutsConcat);
      
      const amountsConcat = Buffer.concat(spentOutputs.map(output => 
        Buffer.from(output.value.toString(16).padStart(16, '0'), 'hex')
      ));
      hashAmounts = taggedHash('TapAmounts', amountsConcat);
      
      const scriptPubkeysConcat = Buffer.concat(spentOutputs.map(output => output.script));
      hashScriptPubkeys = taggedHash('TapScriptPubkeys', scriptPubkeysConcat);
      
      const sequencesConcat = Buffer.concat(transaction.ins.map(input => 
        Buffer.from(input.sequence.toString(16).padStart(8, '0'), 'hex')
      ));
      hashSequences = taggedHash('TapSequences', sequencesConcat);
    }
    
    if ((sigHashType & 0x03) !== 0x02 && (sigHashType & 0x03) !== 0x03) { // Not SIGHASH_SINGLE or SIGHASH_NONE
      const outputsConcat = Buffer.concat(transaction.outs.map(output => 
        Buffer.concat([
          Buffer.from(output.value.toString(16).padStart(16, '0'), 'hex'),
          Buffer.from(output.script.length.toString(16).padStart(2, '0'), 'hex'),
          output.script
        ])
      ));
      hashOutputs = taggedHash('TapOutputs', outputsConcat);
    }
    
    // Build signature message
    const sigMsg = Buffer.concat([
      Buffer.from([0x00]), // epoch
      Buffer.from([sigHashType]),
      Buffer.from(transaction.version.toString(16).padStart(8, '0'), 'hex'),
      Buffer.from(transaction.locktime.toString(16).padStart(8, '0'), 'hex'),
      hashPrevouts,
      hashAmounts,
      hashScriptPubkeys,
      hashSequences,
      hashOutputs,
      Buffer.from([0x00]), // spend_type (key path spending)
      Buffer.from(inputIndex.toString(16).padStart(8, '0'), 'hex')
    ]);
    
    return taggedHash('TapSighash', sigMsg);
  }
}