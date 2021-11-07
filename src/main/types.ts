import { ItemWithEncryptedFields } from "./encryptors"

export enum KeyType {
  ENCRYPTION = 1,
  SIGNING = 2
}

export interface EncryptedItemMetadata<T, U extends keyof T> {
  version: string
  keyId?: string
  nonce: Uint8Array
  encryptedDataKey: Uint8Array
  encryptedFieldNames: U[]
}

export type EncryptedJayZItem<T, U extends keyof T> = ItemWithEncryptedFields<T, U> & {
  __jayz__metadata: EncryptedItemMetadata<T, U>
}
