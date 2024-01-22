export enum KeyType {
  ENCRYPTION = 1,
  SIGNING = 2
}

export enum EncryptionScheme {
  V0_LIBSODIUM // experimental
}

export interface LegacyEncryptedItemMetadata<T, K extends keyof T> {
  scheme: EncryptionScheme
  nonce: Uint8Array
  encryptedDataKey: Uint8Array
  encryptedFieldNames: K[]
}

export interface EncryptedItemMetadataV1 {
  metadataVersion: MetadataVersion.V1
  scheme: EncryptionScheme
  nonce: Uint8Array
  encryptedDataKey: Uint8Array
  encryptedFields: Uint8Array
}

export type itemToEncrypt<T, K extends keyof T> = {
  [P in K]: T[P]
}

export type ItemWithEncryptedFields<T, K extends keyof T> = Omit<T, K> &
  {
    [P in K]: Uint8Array
  }

export type ItemWithoutEncryptedFields<T, K extends keyof T> = Omit<T, K>

export type EncryptedJayZItem<T, K extends keyof T> = LegacyEncryptedJayZItem<T, K> | EncryptedJayZItemV1<T, K>

export type LegacyEncryptedJayZItem<T, K extends keyof T> = ItemWithEncryptedFields<T, K> & {
  __jayz__metadata: LegacyEncryptedItemMetadata<T, K>
}

export type EncryptedJayZItemV1<T, K extends keyof T> = ItemWithoutEncryptedFields<T, K> & {
  __jayz__metadata: EncryptedItemMetadataV1
}

export enum MetadataVersion {
  V1
}
