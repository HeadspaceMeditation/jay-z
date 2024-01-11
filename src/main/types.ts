export enum KeyType {
  ENCRYPTION = 1,
  SIGNING = 2
}

export enum EncryptionScheme {
  V0_LIBSODIUM // experimental
}

export type EncryptedItemMetadata<T, K extends keyof T> = {
  scheme: EncryptionScheme
  nonce: Uint8Array
  encryptedDataKey: Uint8Array
  encryptedFieldNames: K[]
}

export type ItemWithEncryptedFields<T, K extends keyof T> = Omit<T, K> &
  {
    [P in K]: Uint8Array
  }

export type EncryptedJayZItem<T, K extends keyof T> = ItemWithEncryptedFields<
  T,
  K
> & {
  __jayz__metadata: EncryptedItemMetadata<T, K>
}
