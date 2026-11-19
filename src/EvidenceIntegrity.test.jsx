import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import EvidenceIntegrity from './EvidenceIntegrity';

const record = {
  id: 'synthetic-evidence-id',
  sha256: 'a'.repeat(64),
};

test('displays the complete SHA-256 hash and copies it with confirmation', async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText },
  });
  render(<EvidenceIntegrity database={{}} record={record} />);

  expect(screen.getByLabelText('Full SHA-256 hash').textContent).toBe(record.sha256);
  fireEvent.click(screen.getByRole('button', { name: 'Copy Hash' }));

  await waitFor(() => expect(writeText).toHaveBeenCalledWith(record.sha256));
  expect((await screen.findByRole('status')).textContent).toContain('Hash copied.');
});

test('reports matching and mismatching file-integrity results with verification time', async () => {
  const verifiedAt = '2026-10-31T00:00:00.000Z';
  const verifyIntegrity = vi.fn()
    .mockResolvedValueOnce({ status: 'MATCH', verifiedAt })
    .mockResolvedValueOnce({ status: 'MISMATCH', verifiedAt });
  const { rerender } = render(<EvidenceIntegrity database={{}} record={record} verifyIntegrity={verifyIntegrity} />);

  fireEvent.click(screen.getByRole('button', { name: 'Verify Integrity' }));
  expect(await screen.findByText('MATCH')).toBeDefined();
  expect(screen.getByText('Decrypted file SHA-256 matches the recorded hash.')).toBeDefined();
  expect(screen.getByText(/^Checked /).getAttribute('dateTime')).toBe(verifiedAt);

  rerender(<EvidenceIntegrity database={{}} record={record} verifyIntegrity={verifyIntegrity} />);
  fireEvent.click(screen.getByRole('button', { name: 'Verify Integrity' }));
  expect(await screen.findByText('MISMATCH')).toBeDefined();
  expect(screen.getByText('Decrypted file SHA-256 does not match the recorded hash.')).toBeDefined();
});

test('shows verification errors without a MATCH result', async () => {
  const verifyIntegrity = vi.fn().mockRejectedValue(new Error('Evidence could not be decrypted.'));
  render(<EvidenceIntegrity database={{}} record={record} verifyIntegrity={verifyIntegrity} />);

  fireEvent.click(screen.getByRole('button', { name: 'Verify Integrity' }));

  expect(await screen.findByText('ERROR')).toBeDefined();
  expect(screen.getByText('Evidence could not be decrypted.')).toBeDefined();
  expect(screen.queryByText('MATCH')).toBeNull();
  expect(screen.getByText(/^Checked /).hasAttribute('dateTime')).toBe(true);
});
