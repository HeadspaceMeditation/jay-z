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

export type EncryptedJayZItem<T, U extends keyof T> = ItemWithEncryptedFields<T, U> & {
  __jayz__metadata: EncryptedItemMetadata<T, U>
}

export type ItemWithEncryptedFields<T, U extends keyof T> = Omit<T, U> & {
  [K in U]: Uint8Array
}

export interface EncryptedItemMetadata<T, U extends keyof T> {
  version: string
  keyId?: string
  nonce: Uint8Array
  encryptedDataKey: Uint8Array
  encryptedFieldNames: U[]
}
