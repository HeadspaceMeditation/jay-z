export interface KeyProvider {
  generateDataKey(): Promise<GenerateDataKeyResult>
  decryptDataKey(encryptedDataKey: Uint8Array, metadata?: KeyMetadata): Promise<DecryptDataKeyResult>
}

export interface GenerateDataKeyResult {
  plaintextKey: Uint8Array
  encryptedKey: Uint8Array
  metadata?: KeyMetadata
}

export interface DecryptDataKeyResult {
  plaintextKey: Uint8Array
}

export interface KeyMetadata {
  keyId: string
}
