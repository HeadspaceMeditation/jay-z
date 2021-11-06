import { ItemWithEncryptedFields } from "./types"

export interface Encryptor {
  readonly version: string
  encrypt<T, U extends keyof T>(props: EncryptProps<T, U>): EncryptResult<T, U>
  decrypt<T, U extends keyof T>(params: DecryptProps<T, U>): DecryptResult<T>
}

export interface EncryptProps<T, U extends keyof T> {
  item: T
  key: Uint8Array
  fieldsToEncrypt: U[]
}

export interface EncryptResult<T, U extends keyof T> {
  encryptedItem: ItemWithEncryptedFields<T, U>
  nonce: Uint8Array
}

export interface DecryptProps<T, U extends keyof T> {
  item: ItemWithEncryptedFields<T, U>
  key: Uint8Array
  nonce: Uint8Array
  fieldsToDecrypt: U[]
}

export interface DecryptResult<T> {
  decryptedItem: T
}
