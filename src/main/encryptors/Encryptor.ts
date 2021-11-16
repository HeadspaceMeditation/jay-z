export interface Encryptor {
  readonly version: string
  encrypt<T, U extends keyof T>(props: EncryptProps<T, U>): Promise<EncryptResult<T, U>>
  decrypt<T, U extends keyof T>(params: DecryptProps<T, U>): Promise<DecryptResult<T>>
}

export interface EncryptProps<T, U extends keyof T> {
  item: T
  fieldsToEncrypt: U[]
}

export interface DecryptProps<T, U extends keyof T> {
  item: EncryptedJayZItem<T, U>
}

export interface EncryptResult<T, U extends keyof T> {
  encryptedItem: EncryptedJayZItem<T, U>
}

export interface DecryptResult<T> {
  decryptedItem: T
}

export type EncryptedJayZItem<T, U extends keyof T> = LegacyEncryptedJayZItem<T, U> | EncryptedJayZItemV1<T, U>

export type LegacyEncryptedJayZItem<T, U extends keyof T> = ItemWithEncryptedFields<T, U> & {
  __jayz__metadata: {
    version: string
    keyId?: string
    nonce: Uint8Array
    encryptedDataKey: Uint8Array
    encryptedFieldNames: U[]
  }
}

export type EncryptedJayZItemV1<T, U extends keyof T> = Omit<T, U> & {
  __jayz__metadata: {
    metadataVersion: MetadataVersion.V1
    encryptorId: string
    keyId?: string
    nonce: Uint8Array
    encryptedDataKey: Uint8Array
    encryptedFields: Uint8Array
  }
}

export function isLegacyJayZItem<T, U extends keyof T>(
  item: EncryptedJayZItem<T, U>
): item is LegacyEncryptedJayZItem<T, U> {
  return (item as any).__jayz__metadata.encryptedFieldNames !== undefined
}

export enum MetadataVersion {
  V1
}

export type ItemWithEncryptedFields<T, U extends keyof T> = Omit<T, U> & {
  [K in U]: Uint8Array
}
