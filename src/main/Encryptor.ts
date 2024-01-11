import { EncryptionScheme, ItemWithEncryptedFields } from "./types"

export type EncryptParams<T, K extends keyof T> = {
  item: T
  fieldsToEncrypt: K[]
  dataKey: Uint8Array
}

export type EncryptResult<T, K extends keyof T> = {
  encryptedItem: ItemWithEncryptedFields<T, K>
  nonce: Uint8Array
}

export type DecryptParams<T, K extends keyof T> = {
  encryptedItem: ItemWithEncryptedFields<T, K>
  fieldsToDecrypt: K[]
  dataKey: Uint8Array
  nonce: Uint8Array
}

export type DecryptResult<T> = {
  decryptedItem: T
}

export interface Encryptor {
  readonly scheme: EncryptionScheme

  encrypt<T, K extends keyof T>(
    params: EncryptParams<T, K>
  ): EncryptResult<T, K>

  decrypt<T, K extends keyof T>(params: DecryptParams<T, K>): DecryptResult<T>
}
