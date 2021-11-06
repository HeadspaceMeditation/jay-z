export enum KeyType {
  ENCRYPTION = 1,
  SIGNING = 2
}

export interface EncryptedItemMetadata<T, U extends keyof T> {
  version: string
  nonce: Uint8Array
  encryptedDataKey: Uint8Array
  encryptedFieldNames: U[]
}

export type ItemWithEncryptedFields<T, U extends keyof T> = Omit<T, U> & {
  [K in U]: Uint8Array
}

export type EncryptedJayZItem<T, U extends keyof T> = ItemWithEncryptedFields<
  T,
  U
> & {
  __jayz__metadata: EncryptedItemMetadata<T, U>
}
