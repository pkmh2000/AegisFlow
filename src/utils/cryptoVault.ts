// Client-side AES-256-GCM + PBKDF2 + SHA-256 Ransomware-Resistant Backup Vault

export interface EncryptedVaultFile {
  format: 'aegisvault-v1';
  createdAt: string;
  cipher: 'AES-256-GCM';
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  salt: string;
  iv: string;
  sha256Plaintext: string;
  ciphertext: string;
  recordCount: number;
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function fromBase64(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function deriveAesKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function createEncryptedVault(
  payload: unknown,
  passphrase: string,
  recordCount: number
): Promise<{ vault: EncryptedVaultFile; jsonString: string }> {
  const enc = new TextEncoder();
  const plaintextStr = JSON.stringify(payload);
  const plaintextBytes = enc.encode(plaintextStr);

  const hashBuffer = await crypto.subtle.digest('SHA-256', plaintextBytes);
  const sha256Plaintext = toHex(hashBuffer);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iterations = 150000;
  const key = await deriveAesKey(passphrase, salt, iterations);

  const encryptedBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    key,
    plaintextBytes
  );

  const vault: EncryptedVaultFile = {
    format: 'aegisvault-v1',
    createdAt: new Date().toISOString(),
    cipher: 'AES-256-GCM',
    kdf: 'PBKDF2-SHA256',
    iterations,
    salt: toBase64(salt),
    iv: toBase64(iv),
    sha256Plaintext,
    ciphertext: toBase64(new Uint8Array(encryptedBuf)),
    recordCount,
  };

  return {
    vault,
    jsonString: JSON.stringify(vault, null, 2),
  };
}

export async function decryptAndVerifyVault<T>(
  vaultJson: string,
  passphrase: string
): Promise<{ data: T; verified: boolean; sha256: string; createdAt: string }> {
  const parsed = JSON.parse(vaultJson) as EncryptedVaultFile;
  if (parsed.format !== 'aegisvault-v1' || !parsed.salt || !parsed.iv || !parsed.ciphertext) {
    throw new Error('檔案格式不符，請選擇有效的 .aegisvault 加密備份檔。');
  }

  const salt = fromBase64(parsed.salt);
  const iv = fromBase64(parsed.iv);
  const ciphertext = fromBase64(parsed.ciphertext);

  const key = await deriveAesKey(passphrase, salt, parsed.iterations || 150000);
  let decryptedBuf: ArrayBuffer;
  try {
    decryptedBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as BufferSource },
      key,
      ciphertext as BufferSource
    );
  } catch {
    throw new Error('解密失敗：密碼錯誤或備份檔案已遭竄改。');
  }

  const hashBuffer = await crypto.subtle.digest('SHA-256', decryptedBuf);
  const computedSha = toHex(hashBuffer);
  const verified = computedSha === parsed.sha256Plaintext;
  if (!verified) {
    throw new Error('SHA-256 完整性校驗失敗，檔案可能已損毀。');
  }

  const dec = new TextDecoder();
  const data = JSON.parse(dec.decode(decryptedBuf)) as T;
  return {
    data,
    verified,
    sha256: computedSha,
    createdAt: parsed.createdAt,
  };
}
