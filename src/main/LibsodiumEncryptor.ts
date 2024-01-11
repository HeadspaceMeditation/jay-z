import stringify from "fast-json-stable-stringify"
import {
  crypto_kdf_derive_from_key,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  from_string,
  memzero,
  randombytes_buf,
  ready,
  to_string
} from "libsodium-wrappers"
import {
  DecryptParams,
  DecryptResult,
  Encryptor,
  EncryptParams,
  EncryptResult
} from "./Encryptor"
import { EncryptionScheme, ItemWithEncryptedFields, KeyType } from "./types"

/** JSON.parse returns this object, which isn't a node Buffer */
export type JSONBuffer = {
  data: Array<number>
  type: "Buffer"
}

export class LibsodiumEncryptor implements Encryptor {
  public readonly scheme = EncryptionScheme.V0_LIBSODIUM

  encrypt<T, K extends keyof T>(
    params: EncryptParams<T, K>
  ): EncryptResult<T, K> {
    const { item, fieldsToEncrypt, dataKey } = params
    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES)
    const encryptionKey = this.deriveKey(dataKey, KeyType.ENCRYPTION)

    const encryptedFields: {
      [P in K]: Uint8Array
    } = {} as ItemWithEncryptedFields<T, K>

    fieldsToEncrypt.forEach((fieldName) => {
      const fieldValue = item[fieldName]
      if (fieldValue !== undefined && fieldValue !== null) {
        encryptedFields[fieldName] = crypto_secretbox_easy(
          this.toBuffer(fieldValue),
          nonce,
          encryptionKey
        )
      }
    })

    memzero(encryptionKey)

    const encryptedItem = { ...item, ...encryptedFields }
    return { encryptedItem, nonce }
  }

  decrypt<T, K extends keyof T>(params: DecryptParams<T, K>): DecryptResult<T> {
    const { encryptedItem, fieldsToDecrypt, nonce, dataKey } = params
    const decryptionKey = this.deriveKey(dataKey, KeyType.ENCRYPTION)

    const decryptedItem: { [P in keyof T]: T[P] } = {
      ...encryptedItem
    } as any

    fieldsToDecrypt.forEach((fieldName) => {
      const cipherText = encryptedItem[fieldName]
      if (cipherText) {
        const jsonBytes = crypto_secretbox_open_easy(
          cipherText,
          nonce,
          decryptionKey
        )
        const fieldValue = JSON.parse(to_string(jsonBytes))

        // If you JSON.parse an object with a binary field that was stringified,
        // you don't get a Buffer/Uint8Array back but rather a JSON representation of it
        // So we special case here to convert JSON representations of buffers back to the expected type.
        decryptedItem[fieldName] = this.convertBinaryFieldsToBuffers(fieldValue)
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

  private convertBinaryFieldsToBuffers(obj: any): any {
    if (this.isJSONBuffer(obj)) {
      return Buffer.from(obj)
    } else if (typeof obj === "object") {
      Object.keys(obj).forEach((key) => {
        obj[key] = this.convertBinaryFieldsToBuffers(obj[key])
      })
    }

    return obj
  }

  private isJSONBuffer(obj: any): obj is JSONBuffer {
    return (
      obj !== undefined && obj.data instanceof Array && obj.type === "Buffer"
    )
  }

  private toBuffer<T extends {}>(value: T): Uint8Array {
    const json = stringify(value)
    return from_string(json)
  }
}
