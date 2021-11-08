import stringify from "fast-json-stable-stringify"
import { crypto_secretbox_easy, from_string } from "libsodium-wrappers"
import { LibsodiumEncryptor } from "../../main/encryptors"
import { FixedKeyProvider } from "../../main/key-providers"
import { aBankAccount, BankAccount } from "../util"

describe("LibsodiumEncryptor", () => {
  const account = aBankAccount()
  const fieldsToEncrypt: (keyof BankAccount)[] = ["accountNumber", "balance", "routingNumber", "notes"]

  it("should encrypt an item", async () => {
    const { keyProvider, encryptor } = await setup()
    const { plaintextKey } = await keyProvider.generateDataKey()
    const { encryptedItem } = await encryptor.encrypt({
      item: account,
      fieldsToEncrypt
    })

    expect(encryptedItem.pk).toEqual("account-123")
    expect(encryptedItem.sk).toEqual("Flava Flav")

    fieldsToEncrypt.forEach((fieldName) => {
      const expectedValue = crypto_secretbox_easy(
        from_string(stringify(account[fieldName])),
        encryptedItem.__jayz__metadata.nonce,
        plaintextKey
      )
      expect(encryptedItem[fieldName]).toEqual(expectedValue)
    })
  })

  it("should decrypt an item", async () => {
    const { encryptor } = await setup()
    const { encryptedItem } = await encryptor.encrypt({ item: account, fieldsToEncrypt })
    const { decryptedItem } = await encryptor.decrypt({ item: encryptedItem })
    expect(decryptedItem).toEqual(account)
  })

  it("should encrypt and decrypt an item with an undefined or null field", async () => {
    const { encryptor } = await setup()
    const fieldsToEncrypt: (keyof BankAccount)[] = ["accountNumber", "balance", "routingNumber", "notes", "bankName"]

    const emptyValues = [undefined, null]
    const promises = emptyValues.map(async (emptyValue) => {
      const item = { ...account, bankName: emptyValue }
      const { encryptedItem } = await encryptor.encrypt({ item, fieldsToEncrypt })
      const { decryptedItem } = await encryptor.decrypt({ item: encryptedItem })
      expect(decryptedItem).toEqual(item)
    })

    await Promise.all(promises)
  })

  it("should encrypt and decrypt binary fields", async () => {
    const { encryptor } = await setup()
    const binaryItem = {
      name: "hello world",
      binaryData: Buffer.from("hello world", "utf-8")
    }

    const { encryptedItem } = await encryptor.encrypt({ item: binaryItem, fieldsToEncrypt: ["name", "binaryData"] })
    const { decryptedItem } = await encryptor.decrypt({ item: encryptedItem })
    expect(decryptedItem).toEqual(binaryItem)
  })

  it("should encrypt and decrypt binary fields recursively", async () => {
    const { encryptor } = await setup()
    const binaryItem = {
      name: "hello world",
      data: {
        otherData: {
          binaryData: Buffer.from("hello world", "utf-8")
        }
      }
    }

    const { encryptedItem } = await encryptor.encrypt({ item: binaryItem, fieldsToEncrypt: ["name", "data"] })
    const { decryptedItem } = await encryptor.decrypt({ item: encryptedItem })
    expect(decryptedItem).toEqual(binaryItem)
  })
})

async function setup(): Promise<{ keyProvider: FixedKeyProvider; encryptor: LibsodiumEncryptor }> {
  const keyProvider = await FixedKeyProvider.forLibsodium()
  const encryptor = new LibsodiumEncryptor({ keyProvider })
  return { encryptor, keyProvider }
}
