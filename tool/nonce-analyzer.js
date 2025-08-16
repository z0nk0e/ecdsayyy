// nonce-analyzer.js - Complete analyzer implementation
import { SignatureExtractor } from './signature-extractors';
import { SECP256K1_N } from './crypto-utils';

export class NonceReuseAnalyzer {
  constructor(rpc, network = 'mainnet') {
    this.rpc = rpc;
    this.network = network;
    this.extractor = new SignatureExtractor();
    
    // ECDSA signature storage
    this.ecdsaSignatures = [];
    this.ecdsaByRQ = new Map(); // Map of "r:pubkey" -> signatures
    
    // Schnorr signature storage
    this.schnorrSignatures = [];
    this.schnorrByRQ = new Map(); // Map of "r_x:pubkey" -> signatures
  }

  async analyzeTransaction(txData, blockHeight = null) {
    const txid = txData.txid || txData.hash;
    
    // Get full transaction if we only have the hash
    if (!txData.hex) {
      txData = await this.rpc.getRawTransaction(txid, true);
    }
    
    // Process each input
    for (let i = 0; i < txData.vin.length; i++) {
      const vin = txData.vin[i];
      
      // Skip coinbase transactions
      if (vin.coinbase) continue;
      
      // Get the previous output being spent
      let prevout;
      if (vin.prevout) {
        // Already included in response (verbosity=2 in getblock)
        prevout = vin.prevout;
      } else {
        // Need to fetch it
        try {
          const prevTx = await this.rpc.getRawTransaction(vin.txid, true);
          prevout = prevTx.vout[vin.vout];
        } catch (error) {
          console.error(`Failed to fetch prevout for ${vin.txid}:${vin.vout}`);
          continue;
        }
      }
      
      // Extract ECDSA signatures
      const ecdsaSigs = this.extractor.extractECDSASignatures(txData, vin, prevout);
      for (const sig of ecdsaSigs) {
        this.addECDSASignature({
          ...sig,
          txid,
          vin: i,
          blockHeight
        });
      }
      
      // Extract Schnorr signatures
      const schnorrSigs = this.extractor.extractSchnorrSignatures(txData, vin, prevout);
      for (const sig of schnorrSigs) {
        this.addSchnorrSignature({
          ...sig,
          txid,
          vin: i,
          blockHeight
        });
      }
    }
  }

  addECDSASignature(sig) {
    this.ecdsaSignatures.push(sig);
    
    const key = `${sig.r}:${sig.pubkey}`;
    if (!this.ecdsaByRQ.has(key)) {
      this.ecdsaByRQ.set(key, []);
    }
    this.ecdsaByRQ.get(key).push(sig);
  }

  addSchnorrSignature(sig) {
    this.schnorrSignatures.push(sig);
    
    const key = `${sig.r_x}:${sig.pubkeyXOnly}`;
    if (!this.schnorrByRQ.has(key)) {
      this.schnorrByRQ.set(key, []);
    }
    this.schnorrByRQ.get(key).push(sig);
  }

  async analyzeBlockRange(startHeight, endHeight, options = {}) {
    const { onProgress, concurrency = 1 } = options;
    const total = endHeight - startHeight + 1;
    let processed = 0;
    
    for (let height = startHeight; height <= endHeight; height++) {
      try {
        const blockHash = await this.rpc.getBlockHash(height);
        const block = await this.rpc.getBlock(blockHash, 2); // verbosity=2 includes tx details
        
        for (const tx of block.tx) {
          await this.analyzeTransaction(tx, height);
        }
        
        processed++;
        if (onProgress) {
          onProgress({
            current: processed,
            total,
            percentage: (processed / total) * 100,
            currentHeight: height
          });
        }
      } catch (error) {
        console.error(`Error processing block ${height}:`, error);
      }
    }
  }

  detectNonceReuse() {
    const findings = {
      ecdsa: [],
      schnorr: []
    };
    
    // Check ECDSA signatures
    for (const [key, sigs] of this.ecdsaByRQ) {
      if (sigs.length >= 2) {
        // Check if we have different (s, z) pairs for same (r, pubkey)
        const uniquePairs = new Set(sigs.map(sig => `${sig.s}:${sig.z}`));
        
        if (uniquePairs.size >= 2) {
          const [r, pubkey] = key.split(':');
          findings.ecdsa.push({
            type: 'duplicate_r_pubkey',
            r,
            pubkey,
            occurrences: sigs.length,
            uniquePairs: uniquePairs.size,
            transactions: sigs.map(s => ({
              txid: s.txid,
              vin: s.vin,
              blockHeight: s.blockHeight
            }))
          });
        }
      }
    }
    
    // Check Schnorr signatures
    for (const [key, sigs] of this.schnorrByRQ) {
      if (sigs.length >= 2) {
        // Check if we have different (s, e) pairs for same (r_x, pubkey)
        const uniquePairs = new Set(sigs.map(sig => `${sig.s}:${sig.e}`));
        
        if (uniquePairs.size >= 2) {
          const [r_x, pubkeyXOnly] = key.split(':');
          findings.schnorr.push({
            type: 'duplicate_r_pubkey',
            r_x,
            pubkeyXOnly,
            occurrences: sigs.length,
            uniquePairs: uniquePairs.size,
            transactions: sigs.map(s => ({
              txid: s.txid,
              vin: s.vin,
              blockHeight: s.blockHeight
            }))
          });
        }
      }
    }
    
    return findings;
  }

  getStatistics() {
    const uniqueECDSA_R = new Set(this.ecdsaSignatures.map(s => s.r.toString()));
    const uniqueECDSA_Pubkeys = new Set(this.ecdsaSignatures.map(s => s.pubkey));
    const uniqueSchnorr_R = new Set(this.schnorrSignatures.map(s => s.r_x.toString()));
    const uniqueSchnorr_Pubkeys = new Set(this.schnorrSignatures.map(s => s.pubkeyXOnly));
    
    return {
      ecdsa: {
        totalSignatures: this.ecdsaSignatures.length,
        uniqueR: uniqueECDSA_R.size,
        uniquePubkeys: uniqueECDSA_Pubkeys.size,
        potentialLeaks: Array.from(this.ecdsaByRQ.values()).filter(sigs => sigs.length >= 2).length
      },
      schnorr: {
        totalSignatures: this.schnorrSignatures.length,
        uniqueR: uniqueSchnorr_R.size,
        uniquePubkeys: uniqueSchnorr_Pubkeys.size,
        potentialLeaks: Array.from(this.schnorrByRQ.values()).filter(sigs => sigs.length >= 2).length
      }
    };
  }
}