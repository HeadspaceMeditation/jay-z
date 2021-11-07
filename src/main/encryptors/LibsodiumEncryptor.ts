import {
  crypto_secretbox_easy,
  crypto_secretbox_NONCEBYTES,
  crypto_secretbox_open_easy,
  randombytes_buf
} from "libsodium-wrappers"
import {
  DecryptProps,
  DecryptResult,
  Encryptor,
  EncryptProps,
  EncryptResult,
  ItemWithEncryptedFields
} from "./Encryptor"
import { deserialize, serialize } from "./serialization"

enum LibsodiumEncryptorVersion {
  v0 = "v0_libsodium"
}

export class LibsodiumEncryptor implements Encryptor {
  readonly version = LibsodiumEncryptorVersion.v0

  encrypt<T, U extends keyof T>(props: EncryptProps<T, U>): EncryptResult<T, U> {
    const { item, fieldsToEncrypt, key } = props
    const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES)

    const encryptedFields: {
      [K in U]: Uint8Array
    } = {} as ItemWithEncryptedFields<T, U>

    fieldsToEncrypt.forEach((fieldName) => {
      const fieldValue = item[fieldName]
      if (fieldValue !== undefined && fieldValue !== null) {
        encryptedFields[fieldName] = crypto_secretbox_easy(serialize(fieldValue), nonce, key)
      }
    })

    const encryptedItem = { ...item, ...encryptedFields }
    return { encryptedItem, nonce }
  }

  decrypt<T, U extends keyof T>(props: DecryptProps<T, U>): DecryptResult<T> {
    const { item, fieldsToDecrypt, nonce, key } = props

    const decryptedItem: { [P in keyof T]: T[P] } = {
      ...item
    } as any

    fieldsToDecrypt.forEach((fieldName) => {
      const cipherText = item[fieldName]
      if (cipherText) {
        const jsonBytes = crypto_secretbox_open_easy(cipherText, nonce, key)
        decryptedItem[fieldName] = deserialize(jsonBytes)
      }
    })

    return { decryptedItem }
  }
}
