// main.js - Main application with React component
import React, { useState, useCallback } from 'react';
import { BitcoinRPC } from './bitcoin-rpc';
import { NonceReuseAnalyzer } from './nonce-analyzer';
import { PrivateKeySolver } from './private-key-solver';

export function NonceReuseDetector() {
  const [status, setStatus] = useState('idle');
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [config, setConfig] = useState({
    rpcUrl: process.env.REACT_APP_RPC_URL || 'http://localhost:8332',
    rpcUser: process.env.REACT_APP_RPC_USER || '',
    rpcPassword: process.env.REACT_APP_RPC_PASSWORD || '',
    startBlock: 800000,
    endBlock: 800010,
    network: 'mainnet'
  });

  const analyze = useCallback(async () => {
    setStatus('analyzing');
    setError(null);
    setProgress(0);
    
    try {
      // Initialize RPC client
      const rpc = new BitcoinRPC(
        config.rpcUrl,
        config.rpcUser,
        config.rpcPassword
      );
      
      // Verify connection
      const info = await rpc.getBlockchainInfo();
      console.log(`Connected to ${info.chain} at height ${info.blocks}`);
      
      // Initialize analyzer
      const analyzer = new NonceReuseAnalyzer(rpc, config.network);
      
      // Analyze block range
      await analyzer.analyzeBlockRange(
        config.startBlock,
        config.endBlock,
        {
          onProgress: (prog) => {
            setProgress(prog.percentage);
            console.log(`Processing block ${prog.currentHeight}`);
          }
        }
      );
      
      // Get statistics
      const stats = analyzer.getStatistics();
      
      // Detect nonce reuse
      const findings = analyzer.detectNonceReuse();
      
      // Attempt to recover private keys
      const solver = new PrivateKeySolver(analyzer);
      const recovered = solver.solveAll();
      
      setResults({
        statistics: stats,
        findings: findings,
        recovered: recovered,
        timestamp: new Date().toISOString()
      });
      
      setStatus('complete');
    } catch (err) {
      console.error('Analysis error:', err);
      setError(err.message);
      setStatus('error');
    }
  }, [config]);

  const exportResults = useCallback(() => {
    if (!results) return;
    
    const blob = new Blob([JSON.stringify(results, null, 2)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nonce-reuse-analysis-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [results]);

  return (
    <div className="nonce-reuse-detector">
      <h1>Bitcoin Nonce Reuse Detector</h1>
      
      <div className="config-section">
        <h2>Configuration</h2>
        <div>
          <label>
            RPC URL:
            <input
              type="text"
              value={config.rpcUrl}
              onChange={(e) => setConfig({...config, rpcUrl: e.target.value})}
              disabled={status === 'analyzing'}
            />
          </label>
        </div>
        <div>
          <label>
            RPC Username:
            <input
              type="text"
              value={config.rpcUser}
              onChange={(e) => setConfig({...config, rpcUser: e.target.value})}
              disabled={status === 'analyzing'}
            />
          </label>
        </div>
        <div>
          <label>
            RPC Password:
            <input
              type="password"
              value={config.rpcPassword}
              onChange={(e) => setConfig({...config, rpcPassword: e.target.value})}
              disabled={status === 'analyzing'}
            />
          </label>
        </div>
        <div>
          <label>
            Start Block:
            <input
              type="number"
              value={config.startBlock}
              onChange={(e) => setConfig({...config, startBlock: parseInt(e.target.value)})}
              disabled={status === 'analyzing'}
            />
          </label>
        </div>
        <div>
          <label>
            End Block:
            <input
              type="number"
              value={config.endBlock}
              onChange={(e) => setConfig({...config, endBlock: parseInt(e.target.value)})}
              disabled={status === 'analyzing'}
            />
          </label>
        </div>
      </div>

      <div className="control-section">
        <button 
          onClick={analyze} 
          disabled={status === 'analyzing'}
        >
          {status === 'analyzing' ? 'Analyzing...' : 'Start Analysis'}
        </button>
        
        {results && (
          <button onClick={exportResults}>
            Export Results
          </button>
        )}
      </div>

      {status === 'analyzing' && (
        <div className="progress-section">
          <h3>Progress</h3>
          <progress value={progress} max="100" />
          <span>{progress.toFixed(1)}%</span>
        </div>
      )}

      {error && (
        <div className="error-section">
          <h3>Error</h3>
          <pre>{error}</pre>
        </div>
      )}

      {results && (
        <div className="results-section">
          <h2>Results</h2>
          
          <div className="statistics">
            <h3>Statistics</h3>
            <h4>ECDSA</h4>
            <ul>
              <li>Total Signatures: {results.statistics.ecdsa.totalSignatures}</li>
              <li>Unique R values: {results.statistics.ecdsa.uniqueR}</li>
              <li>Unique Public Keys: {results.statistics.ecdsa.uniquePubkeys}</li>
              <li>Potential Leaks: {results.statistics.ecdsa.potentialLeaks}</li>
            </ul>
            
            <h4>Schnorr (Taproot)</h4>
            <ul>
              <li>Total Signatures: {results.statistics.schnorr.totalSignatures}</li>
              <li>Unique R values: {results.statistics.schnorr.uniqueR}</li>
              <li>Unique Public Keys: {results.statistics.schnorr.uniquePubkeys}</li>
              <li>Potential Leaks: {results.statistics.schnorr.potentialLeaks}</li>
            </ul>
          </div>

          <div className="findings">
            <h3>Nonce Reuse Findings</h3>
            
            {results.findings.ecdsa.length > 0 && (
              <div>
                <h4>ECDSA Vulnerabilities ({results.findings.ecdsa.length})</h4>
                {results.findings.ecdsa.map((finding, i) => (
                  <details key={i}>
                    <summary>
                      Public Key: {finding.pubkey.slice(0, 10)}... 
                      ({finding.occurrences} occurrences)
                    </summary>
                    <pre>{JSON.stringify(finding, null, 2)}</pre>
                  </details>
                ))}
              </div>
            )}
            
            {results.findings.schnorr.length > 0 && (
              <div>
                <h4>Schnorr Vulnerabilities ({results.findings.schnorr.length})</h4>
                {results.findings.schnorr.map((finding, i) => (
                  <details key={i}>
                    <summary>
                      Public Key: {finding.pubkeyXOnly.slice(0, 10)}... 
                      ({finding.occurrences} occurrences)
                    </summary>
                    <pre>{JSON.stringify(finding, null, 2)}</pre>
                  </details>
                ))}
              </div>
            )}
          </div>

          {(results.recovered.ecdsa.keys.length > 0 || 
            results.recovered.schnorr.keys.length > 0) && (
            <div className="recovered-keys">
              <h3>⚠️ Recovered Private Keys</h3>
              <p style={{color: 'red'}}>
                <strong>WARNING:</strong> Private keys have been recovered. 
                Handle with extreme care!
              </p>
              
              {results.recovered.ecdsa.keys.length > 0 && (
                <div>
                  <h4>ECDSA Keys ({results.recovered.ecdsa.keys.length})</h4>
                  {results.recovered.ecdsa.keys.map((key, i) => (
                    <details key={i}>
                      <summary>
                        Address: {key.address}
                      </summary>
                      <pre>{JSON.stringify(key, null, 2)}</pre>
                    </details>
                  ))}
                </div>
              )}
              
              {results.recovered.schnorr.keys.length > 0 && (
                <div>
                  <h4>Taproot Keys ({results.recovered.schnorr.keys.length})</h4>
                  {results.recovered.schnorr.keys.map((key, i) => (
                    <details key={i}>
                      <summary>
                        Address: {key.address}
                      </summary>
                      <pre>{JSON.stringify(key, null, 2)}</pre>
                    </details>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default NonceReuseDetector;