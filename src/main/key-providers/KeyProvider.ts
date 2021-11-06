export interface KeyProvider {
  generateDataKey(): Promise<GenerateDataKeyResult>
  decryptDataKey(encryptedDataKey: Uint8Array): Promise<DecryptDataKeyResult>
}

export interface GenerateDataKeyResult {
  plaintextKey: Uint8Array
  encryptedKey: Uint8Array
}

export interface DecryptDataKeyResult {
  plaintextKey: Uint8Array
}
