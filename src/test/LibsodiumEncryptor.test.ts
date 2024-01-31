import stringify from "fast-json-stable-stringify"
import {
  crypto_kdf_derive_from_key,
  crypto_secretbox_easy,
  crypto_secretbox_KEYBYTES,
  crypto_secretbox_NONCEBYTES,
  from_string,
  memzero,
  randombytes_buf
} from "libsodium-wrappers"
import { FixedDataKeyProvider } from "../main/FixedDataKeyProvider"
import { LibsodiumEncryptor } from "../main/LibsodiumEncryptor"
import { ItemWithEncryptedFields, KeyType } from "../main/types"
import { aBankAccount, BankAccount } from "./util"
import { EncryptParams, LegacyEncryptResult } from "../main/Encryptor"
import { serialize } from "../main/serialization"

describe("LibsodiumEncryptor", () => {
  const account = aBankAccount()
  const encryptor = new LibsodiumEncryptor()
  const fieldsToEncrypt: (keyof BankAccount)[] = [
    "accountNumber",
    "balance",
    "routingNumber",
    "notes"
  ]

  it("should encrypt an item", async () => {
    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const { nonce, encryptedFields } = encryptor.encrypt({
      item: account,
      fieldsToEncrypt,
      dataKey
    })

    const encryptionKey = crypto_kdf_derive_from_key(
      crypto_secretbox_KEYBYTES,
      KeyType.ENCRYPTION,
      "__jayz__",
      dataKey
    )

    const fields = {} as any
    fieldsToEncrypt.forEach((fieldName) => {
      fields[fieldName] = account[fieldName]
    })

    const encryptedItemFields = crypto_secretbox_easy(
      from_string(stringify(fields)),
      nonce,
      encryptionKey
    )

    expect(encryptedFields).toEqual(encryptedItemFields)
  })

  it("should encrypt a legacy item", async () => {
    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const { encryptedItem, nonce } = legacyEncrypt({
      item: account,
      fieldsToEncrypt,
      dataKey
    })

    expect(encryptedItem.pk).toEqual("account-123")
    expect(encryptedItem.sk).toEqual("Flava Flav")

    const encryptionKey = crypto_kdf_derive_from_key(
      crypto_secretbox_KEYBYTES,
      KeyType.ENCRYPTION,
      "__jayz__",
      dataKey
    )

    fieldsToEncrypt.forEach((fieldName) => {
      const expectedValue = crypto_secretbox_easy(
        from_string(stringify(account[fieldName])),
        nonce,
        encryptionKey
      )

      expect(encryptedItem[fieldName]).toEqual(expectedValue)
    })
  })

  it("should decrypt an item", async () => {
    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const { plaintextFields, nonce, encryptedFields } = encryptor.encrypt({
      item: account,
      fieldsToEncrypt,
      dataKey
    })

    const { decryptedItem } = encryptor.decrypt({
      encryptedItem: plaintextFields,
      nonce,
      dataKey,
      encryptedFields
    })

    expect(decryptedItem).toEqual(account)
  })

  it("should decrypt a legacy item", async () => {
    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const { encryptedItem, nonce } = legacyEncrypt({
      item: account,
      fieldsToEncrypt,
      dataKey
    })

    const { decryptedItem } = encryptor.decrypt({
      encryptedItem,
      nonce,
      dataKey,
      fieldsToDecrypt: fieldsToEncrypt
    })

    expect(decryptedItem).toEqual(account)
  })

  it("should encrypt and decrypt an item with an undefined or null field", async () => {
    const fieldsToEncrypt: (keyof BankAccount)[] = [
      "accountNumber",
      "balance",
      "routingNumber",
      "notes",
      "bankName"
    ]

    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const emptyValues = [undefined, null]
    emptyValues.forEach((emptyValue) => {
      const item = { ...account, bankName: emptyValue }
      const { plaintextFields, nonce, encryptedFields } = encryptor.encrypt({
        item,
        fieldsToEncrypt,
        dataKey
      })

      const { decryptedItem } = encryptor.decrypt({
        encryptedItem: plaintextFields,
        nonce,
        dataKey,
        encryptedFields
      })

      expect(decryptedItem).toEqual(item)
    })
  })

  it("should encrypt and decrypt binary fields", async () => {
    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const binaryItem = {
      name: "hello world",
      binaryData: Buffer.from("hello world", "utf-8")
    }

    const { plaintextFields, nonce, encryptedFields } = encryptor.encrypt({
      item: binaryItem,
      fieldsToEncrypt: ["name", "binaryData"],
      dataKey
    })

    const { decryptedItem } = encryptor.decrypt({
      encryptedItem: plaintextFields,
      nonce,
      dataKey,
      encryptedFields
    })

    expect(decryptedItem).toEqual(binaryItem)
  })

  it("should encrypt and decrypt binary fields recursively", async () => {
    const dataKeyProvider = await FixedDataKeyProvider.forLibsodium()
    const { dataKey } = await dataKeyProvider.generateDataKey()

    const binaryItem = {
      name: "hello world",
      data: {
        otherData: {
          binaryData: Buffer.from("hello world", "utf-8")
        }
      }
    }

    const { plaintextFields, nonce, encryptedFields } = encryptor.encrypt({
      item: binaryItem,
      fieldsToEncrypt: ["name", "data"],
      dataKey
    })

    const { decryptedItem } = encryptor.decrypt({
      encryptedItem: plaintextFields,
      nonce,
      dataKey,
      encryptedFields
    })

    expect(decryptedItem).toEqual(binaryItem)
  })
})

/** This is a copy/pasted "legacy" version of LibsodiumEncryptor's encrypt function, which had
 *  a bug that reused nonces across multiple encrypt operations.
 *
 *  It is preserved here for testing to ensure we can decrypt items encrypted with this format
 *  */
function legacyEncrypt<T, K extends keyof T>(
  params: EncryptParams<T, K>
): LegacyEncryptResult<T, K> {
  function deriveKey(dataKey: Uint8Array, keyType: KeyType): Uint8Array {
    const key = crypto_kdf_derive_from_key(
      crypto_secretbox_KEYBYTES,
      keyType,
      "__jayz__",
      dataKey
    )
  
    return key
  }

  const { item, fieldsToEncrypt, dataKey } = params
  const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES)
  const encryptionKey = deriveKey(dataKey, KeyType.ENCRYPTION)

  const encryptedFields: {
    [P in K]: Uint8Array
  } = {} as ItemWithEncryptedFields<T, K>

  fieldsToEncrypt.forEach((fieldName) => {
    const fieldValue = item[fieldName]
    if (fieldValue !== undefined && fieldValue !== null) {
      encryptedFields[fieldName] = crypto_secretbox_easy(
        serialize(fieldValue),
        nonce,
        encryptionKey
      )
    }
  })

  memzero(encryptionKey)

  const encryptedItem = { ...item, ...encryptedFields }
  return { encryptedItem, nonce }
}