import {
  crypto_kdf_derive_from_key,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  memzero,
  randombytes_buf
} from "libsodium-wrappers"
import { KeyType } from "../types"
import {
  DecryptProps,
  DecryptResult,
  Encryptor,
  EncryptProps,
  EncryptResult,
  ItemWithEncryptedFields
} from "./Encryptor"
import { deserialize, serialize } from "./serialization"

/** JSON.parse returns this object, which isn't a node Buffer */
export interface JSONBuffer {
  data: Array<number>
  type: "Buffer"
}

enum LibsodiumEncryptorVersion {
  v0 = "v0_libsodium"
}

export class LegacyLibsodiumEncryptor implements Encryptor {
  readonly version = LibsodiumEncryptorVersion.v0

  encrypt<T, U extends keyof T>(props: EncryptProps<T, U>): EncryptResult<T, U> {
    const { item, fieldsToEncrypt, key } = props
    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES)
    const encryptionKey = this.deriveKey(key, KeyType.ENCRYPTION)

    const encryptedFields: {
      [K in U]: Uint8Array
    } = {} as ItemWithEncryptedFields<T, U>

    fieldsToEncrypt.forEach((fieldName) => {
      const fieldValue = item[fieldName]
      if (fieldValue !== undefined && fieldValue !== null) {
        encryptedFields[fieldName] = crypto_secretbox_easy(serialize(fieldValue), nonce, encryptionKey)
      }
    })

    memzero(encryptionKey)
    const encryptedItem = { ...item, ...encryptedFields }
    return { encryptedItem, nonce }
  }

  decrypt<T, U extends keyof T>(props: DecryptProps<T, U>): DecryptResult<T> {
    const { item, fieldsToDecrypt, nonce, key } = props
    const decryptionKey = this.deriveKey(key, KeyType.ENCRYPTION)

    const decryptedItem: { [P in keyof T]: T[P] } = {
      ...item
    } as any

    fieldsToDecrypt.forEach((fieldName) => {
      const cipherText = item[fieldName]
      if (cipherText) {
        const jsonBytes = crypto_secretbox_open_easy(cipherText, nonce, decryptionKey)
        decryptedItem[fieldName] = deserialize(jsonBytes)
      }
    })

    memzero(decryptionKey)
    return { decryptedItem }
  }

  private deriveKey(dataKey: Uint8Array, keyType: KeyType): Uint8Array {
    const key = crypto_kdf_derive_from_key(
      crypto_secretbox_KEYBYTES,
      keyType,
      "__jayz__", // encryption context: must be 8 chars, per https://libsodium.gitbook.io/doc/key_derivation
      dataKey
    )

    return key
  }
}
