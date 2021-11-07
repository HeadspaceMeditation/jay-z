import stringify from "fast-json-stable-stringify"
import { crypto_secretbox_easy, from_string } from "libsodium-wrappers"
import { LibsodiumEncryptor } from "../../main/encryptors"
import { FixedKeyProvider } from "../../main/key-providers"
import { aBankAccount, BankAccount } from "../util"

describe("LibsodiumEncryptor", () => {
  const account = aBankAccount()
  const encryptor = new LibsodiumEncryptor()
  const fieldsToEncrypt: (keyof BankAccount)[] = ["accountNumber", "balance", "routingNumber", "notes"]

  it("should encrypt an item", async () => {
    const dataKeyProvider = await FixedKeyProvider.forLibsodium()
    const { plaintextKey } = await dataKeyProvider.generateDataKey()

    const { encryptedItem, nonce } = encryptor.encrypt({
      item: account,
      fieldsToEncrypt,
      key: plaintextKey
    })

    expect(encryptedItem.pk).toEqual("account-123")
    expect(encryptedItem.sk).toEqual("Flava Flav")

    fieldsToEncrypt.forEach((fieldName) => {
      const expectedValue = crypto_secretbox_easy(from_string(stringify(account[fieldName])), nonce, plaintextKey)
      expect(encryptedItem[fieldName]).toEqual(expectedValue)
    })
  })

  it("should decrypt an item", async () => {
    const dataKeyProvider = await FixedKeyProvider.forLibsodium()
    const { plaintextKey } = await dataKeyProvider.generateDataKey()

    const { encryptedItem, nonce } = encryptor.encrypt({
      item: account,
      fieldsToEncrypt,
      key: plaintextKey
    })

    const { decryptedItem } = encryptor.decrypt({
      item: encryptedItem,
      nonce,
      key: plaintextKey,
      fieldsToDecrypt: fieldsToEncrypt
    })

    expect(decryptedItem).toEqual(account)
  })

  it("should encrypt and decrypt an item with an undefined or null field", async () => {
    const fieldsToEncrypt: (keyof BankAccount)[] = ["accountNumber", "balance", "routingNumber", "notes", "bankName"]

    const dataKeyProvider = await FixedKeyProvider.forLibsodium()
    const { plaintextKey } = await dataKeyProvider.generateDataKey()

    const emptyValues = [undefined, null]
    emptyValues.forEach((emptyValue) => {
      const item = { ...account, bankName: emptyValue }
      const { encryptedItem, nonce } = encryptor.encrypt({
        item,
        fieldsToEncrypt,
        key: plaintextKey
      })

      const { decryptedItem } = encryptor.decrypt({
        item: encryptedItem,
        nonce,
        key: plaintextKey,
        fieldsToDecrypt: fieldsToEncrypt
      })

      expect(decryptedItem).toEqual(item)
    })
  })

  it("should encrypt and decrypt binary fields", async () => {
    const dataKeyProvider = await FixedKeyProvider.forLibsodium()
    const { plaintextKey } = await dataKeyProvider.generateDataKey()

    const binaryItem = {
      name: "hello world",
      binaryData: Buffer.from("hello world", "utf-8")
    }

    const { encryptedItem, nonce } = encryptor.encrypt({
      item: binaryItem,
      fieldsToEncrypt: ["name", "binaryData"],
      key: plaintextKey
    })

    const { decryptedItem } = encryptor.decrypt({
      item: encryptedItem,
      nonce,
      key: plaintextKey,
      fieldsToDecrypt: ["name", "binaryData"]
    })

    expect(decryptedItem).toEqual(binaryItem)
  })

  it("should encrypt and decrypt binary fields recursively", async () => {
    const dataKeyProvider = await FixedKeyProvider.forLibsodium()
    const { plaintextKey } = await dataKeyProvider.generateDataKey()

    const binaryItem = {
      name: "hello world",
      data: {
        otherData: {
          binaryData: Buffer.from("hello world", "utf-8")
        }
      }
    }

    const { encryptedItem, nonce } = encryptor.encrypt({
      item: binaryItem,
      fieldsToEncrypt: ["name", "data"],
      key: plaintextKey
    })

    const { decryptedItem } = encryptor.decrypt({
      item: encryptedItem,
      nonce,
      key: plaintextKey,
      fieldsToDecrypt: ["name", "data"]
    })

    expect(decryptedItem).toEqual(binaryItem)
  })
})