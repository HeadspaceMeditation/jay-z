import stringify from "fast-json-stable-stringify"
import { crypto_secretbox_easy, crypto_secretbox_NONCEBYTES, from_string, randombytes_buf } from "libsodium-wrappers"
import { EncryptProps, EncryptResult, ItemWithEncryptedFields, LibsodiumEncryptor } from "../../main/encryptors"
import { serialize } from "../../main/encryptors/serialization"
import { FixedKeyProvider, KeyProvider } from "../../main/key-providers"
import { aBankAccount, BankAccount } from "../util"

describe("LibsodiumEncryptor", () => {
  const account = aBankAccount()
  const fieldsToEncrypt: (keyof BankAccount)[] = ["accountNumber", "balance", "routingNumber", "notes"]

  it("should encrypt an item", async () => {
    const { keyProvider, encryptor } = await setup()
    const { plaintextKey } = await keyProvider.generateDataKey()
    const { encryptedItem } = await encryptor.encrypt({
      item: account,
      fieldsToEncrypt: ["accountNumber", "balance", "routingNumber", "notes"]
    })

    expect(encryptedItem.pk).toEqual("account-123")
    expect(encryptedItem.sk).toEqual("Flava Flav")

    const fields = {} as any
    fieldsToEncrypt.forEach((fieldName) => {
      fields[fieldName] = account[fieldName]
    })

    const encryptedFields = crypto_secretbox_easy(
      from_string(stringify(fields)),
      encryptedItem.__jayz__metadata.nonce,
      plaintextKey
    )

    expect((encryptedItem.__jayz__metadata as any).encryptedFields).toEqual(encryptedFields)
  })

  it("should decrypt an item", async () => {
    const { encryptor } = await setup()
    const { encryptedItem } = await encryptor.encrypt({ item: account, fieldsToEncrypt })
    const { decryptedItem } = await encryptor.decrypt({ item: encryptedItem })
    expect(decryptedItem).toEqual(account)
  })

  it("should decrypt a legacy item", async () => {
    const { encryptor, keyProvider } = await setup()
    const { encryptedItem } = await legacyEncrypt(keyProvider, { item: account, fieldsToEncrypt })
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

/** This is a copy/pasted "legacy" version of LibsodiumEncryptor's encrypt function, which had
 *  a bug that reused nonces across multiple encrypt operations.
 *
 *  It is preserved here for testing to ensure we can decrypt items encrypted with this format
 *  */
async function legacyEncrypt<T, U extends keyof T>(
  keyProvider: KeyProvider,
  props: EncryptProps<T, U>
): Promise<EncryptResult<T, U>> {
  const { item, fieldsToEncrypt } = props
  const key = await keyProvider.generateDataKey()
  const nonce = randombytes_buf(crypto_secretbox_NONCEBYTES)

  const encryptedFields: {
    [K in U]: Uint8Array
  } = {} as ItemWithEncryptedFields<T, U>

  fieldsToEncrypt.forEach((fieldName) => {
    const fieldValue = item[fieldName]
    if (fieldValue !== undefined && fieldValue !== null) {
      encryptedFields[fieldName] = crypto_secretbox_easy(serialize(fieldValue), nonce, key.plaintextKey)
    }
  })

  const encryptedItem = {
    ...item,
    ...encryptedFields,
    __jayz__metadata: {
      encryptedDataKey: key.encryptedKey,
      keyId: key.metadata?.keyId,
      nonce,
      version: "v0",
      encryptedFieldNames: fieldsToEncrypt
    }
  }

  return { encryptedItem }
}
