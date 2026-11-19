const encoder = new TextEncoder();
const decoder = new TextDecoder();
const KDF_ITERATIONS = 600_000;
const PRIVATE_KEY_AAD = encoder.encode('forensiai-member-private-key-v1');
const CASE_KEY_LABEL = encoder.encode('forensiai-case-key-v1');

function toBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function fromBase64(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function requirePassphrase(passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 12) {
    throw new Error('Use a separate vault passphrase with at least 12 characters.');
  }
}

async function deriveWrappingKey(passphrase, salt, iterations) {
  const material = await crypto.subtle.importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function createMemberKeyBundle(vaultPassphrase) {
  requirePassphrase(vaultPassphrase);
  const keyPair = await crypto.subtle.generateKey({
    name: 'RSA-OAEP',
    modulusLength: 3072,
    publicExponent: Uint8Array.from([1, 0, 1]),
    hash: 'SHA-256',
  }, true, ['encrypt', 'decrypt']);
  const [publicKey, privateKey] = await Promise.all([
    crypto.subtle.exportKey('jwk', keyPair.publicKey),
    crypto.subtle.exportKey('jwk', keyPair.privateKey),
  ]);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await deriveWrappingKey(vaultPassphrase, salt, KDF_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: PRIVATE_KEY_AAD },
    wrappingKey,
    encoder.encode(JSON.stringify(privateKey)),
  );

  return {
    formatVersion: 1,
    publicKeyAlgorithm: 'RSA-OAEP-3072-SHA256',
    publicKey,
    privateKeyEnvelope: {
      formatVersion: 1,
      kdf: 'PBKDF2-SHA256',
      iterations: KDF_ITERATIONS,
      cipher: 'AES-256-GCM',
      salt: toBase64(salt),
      iv: toBase64(iv),
      ciphertext: toBase64(new Uint8Array(ciphertext)),
    },
  };
}

export async function unlockMemberPrivateKey(privateKeyEnvelope, vaultPassphrase) {
  requirePassphrase(vaultPassphrase);
  if (privateKeyEnvelope.formatVersion !== 1 || privateKeyEnvelope.kdf !== 'PBKDF2-SHA256') {
    throw new Error('Unsupported private key envelope version.');
  }
  const salt = fromBase64(privateKeyEnvelope.salt);
  const iv = fromBase64(privateKeyEnvelope.iv);
  const wrappingKey = await deriveWrappingKey(vaultPassphrase, salt, privateKeyEnvelope.iterations);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: PRIVATE_KEY_AAD },
    wrappingKey,
    fromBase64(privateKeyEnvelope.ciphertext),
  );
  const privateJwk = JSON.parse(decoder.decode(plaintext));
  return crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt'],
  );
}

export async function createCaseKeyMaterial() {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  return { key, rawKey };
}

export async function wrapCaseKeyForMember(rawCaseKey, memberPublicJwk) {
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    memberPublicJwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  );
  const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP', label: CASE_KEY_LABEL }, publicKey, rawCaseKey);
  return {
    formatVersion: 1,
    algorithm: 'RSA-OAEP-3072-SHA256',
    ciphertext: toBase64(new Uint8Array(ciphertext)),
  };
}

export async function unwrapCaseKeyForMember(envelope, memberPrivateKey) {
  if (envelope.formatVersion !== 1 || envelope.algorithm !== 'RSA-OAEP-3072-SHA256') {
    throw new Error('Unsupported case key envelope version.');
  }
  const rawCaseKey = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP', label: CASE_KEY_LABEL },
    memberPrivateKey,
    fromBase64(envelope.ciphertext),
  );
  return crypto.subtle.importKey('raw', rawCaseKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
