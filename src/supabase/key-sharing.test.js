import { expect, test } from 'vitest';
import {
  createCaseKeyMaterial,
  createMemberKeyBundle,
  unlockMemberPrivateKey,
  unwrapCaseKeyForMember,
  wrapCaseKeyForMember,
} from './key-sharing';

test('a teammate unwraps only the case key wrapped to their public key', async () => {
  const member = await createMemberKeyBundle('separate-vault-passphrase-2026');
  const otherMember = await createMemberKeyBundle('another-separate-passphrase');
  const privateKey = await unlockMemberPrivateKey(member.privateKeyEnvelope, 'separate-vault-passphrase-2026');
  const otherPrivateKey = await unlockMemberPrivateKey(otherMember.privateKeyEnvelope, 'another-separate-passphrase');
  const { key: caseKey, rawKey } = await createCaseKeyMaterial();
  const envelope = await wrapCaseKeyForMember(rawKey, member.publicKey);
  const sharedKey = await unwrapCaseKeyForMember(envelope, privateKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode('case evidence remains client-encrypted');
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, caseKey, plaintext);
  const recovered = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, sharedKey, ciphertext);

  expect(new TextDecoder().decode(recovered)).toBe('case evidence remains client-encrypted');
  await expect(unlockMemberPrivateKey(member.privateKeyEnvelope, 'wrong-vault-passphrase')).rejects.toThrow();
  await expect(unwrapCaseKeyForMember(envelope, otherPrivateKey)).rejects.toThrow();
});

test('rejects short vault passphrases before creating key material', async () => {
  await expect(createMemberKeyBundle('too-short')).rejects.toThrow(/at least 12 characters/);
});
