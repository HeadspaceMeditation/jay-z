import { EncryptionScheme, ItemWithEncryptedFields, ItemWithoutEncryptedFields } from "./types"

export interface EncryptParams<T, K extends keyof T> {
  item: T
  fieldsToEncrypt: readonly K[]
  dataKey: Uint8Array
}

export interface LegacyEncryptResult<T, K extends keyof T> {
  encryptedItem: ItemWithEncryptedFields<T, K>
  nonce: Uint8Array
}

export interface EncryptResult<T, K extends keyof T> {
  plaintextFields: ItemWithoutEncryptedFields<T,K>
  nonce: Uint8Array
  encryptedFields: Uint8Array
}

export interface LegacyDecryptParams<T, K extends keyof T> {
  encryptedItem: ItemWithEncryptedFields<T, K>
  fieldsToDecrypt: K[]
  dataKey: Uint8Array
  nonce: Uint8Array
}

export interface DecryptParams<T, K extends keyof T> {
  encryptedItem: ItemWithoutEncryptedFields<T,K>
  dataKey: Uint8Array
  nonce: Uint8Array
  encryptedFields: Uint8Array
}

export interface DecryptResult<T> {
  decryptedItem: T
}

export interface Encryptor {
  readonly scheme: EncryptionScheme

  encrypt<T, K extends keyof T>(
    params: EncryptParams<T, K>
    ): EncryptResult<T, K>
    
  decrypt<T, K extends keyof T>(params: DecryptParams<T, K> | LegacyDecryptParams<T,K>): DecryptResult<T>
}
