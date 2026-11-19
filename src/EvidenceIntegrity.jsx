import { useState } from 'react';
import { verifyEvidenceIntegrity } from './vault';

function formatVerificationTime(value) {
  return new Date(value).toLocaleString();
}

export default function EvidenceIntegrity({ database, record, verifyIntegrity = verifyEvidenceIntegrity }) {
  const [copyMessage, setCopyMessage] = useState('');
  const [verification, setVerification] = useState(null);
  const [busy, setBusy] = useState(false);

  const copyHash = async () => {
    try {
      await navigator.clipboard.writeText(record.sha256);
      setCopyMessage('Hash copied.');
    } catch {
      setCopyMessage('Could not copy hash. Check clipboard permissions.');
    }
  };

  const verify = async () => {
    setBusy(true);
    setVerification({ status: 'VERIFYING' });
    try {
      setVerification(await verifyIntegrity(database, record.id, record.sha256));
    } catch (error) {
      setVerification({
        status: 'ERROR',
        verifiedAt: new Date().toISOString(),
        message: error.message || 'Evidence integrity verification failed.',
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="evidence-integrity" aria-labelledby="evidence-integrity-title">
      <div className="detail-section-title">
        <h3 id="evidence-integrity-title">SHA-256 file integrity</h3>
        <span>64-CHARACTER HASH</span>
      </div>
      <code className="evidence-hash" aria-label="Full SHA-256 hash">{record.sha256}</code>
      <div className="integrity-actions">
        <button type="button" className="button button-dark" onClick={copyHash}>Copy Hash</button>
        <button type="button" className="button button-dark" onClick={verify} disabled={busy || !database}>
          {busy ? 'Verifying…' : 'Verify Integrity'}
        </button>
      </div>
      {copyMessage && <p className="integrity-feedback" role="status">{copyMessage}</p>}
      {verification && (
        <div className={`file-integrity-result file-integrity-${verification.status.toLowerCase()}`} role="status" aria-live="polite">
          <strong>{verification.status}</strong>
          {verification.status === 'MATCH' && <span>Decrypted file SHA-256 matches the recorded hash.</span>}
          {verification.status === 'MISMATCH' && <span>Decrypted file SHA-256 does not match the recorded hash.</span>}
          {verification.status === 'ERROR' && <span>{verification.message}</span>}
          {verification.verifiedAt && <time dateTime={verification.verifiedAt}>Checked {formatVerificationTime(verification.verifiedAt)}</time>}
        </div>
      )}
      <p className="integrity-separation-note">File-content integrity is separate from the chain-of-custody check above.</p>
    </section>
  );
}
