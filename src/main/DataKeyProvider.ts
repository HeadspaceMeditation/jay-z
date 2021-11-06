export interface DataKeyProvider {
  generateDataKey(): Promise<DataKey>
  decryptDataKey(encryptedDataKey: Uint8Array): Promise<Uint8Array>
}

export interface DataKey {
  plaintextKey: Uint8Array
  encryptedKey: Uint8Array
}
