export interface DataKeyProvider {
  generateDataKey(): Promise<DataKey>
  decryptDataKey(encryptedDataKey: Uint8Array): Promise<Uint8Array>
}

export type DataKey = {
  dataKey: Uint8Array
  encryptedDataKey: Uint8Array
}
