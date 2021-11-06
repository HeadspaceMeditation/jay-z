import {
  crypto_kdf_KEYBYTES,
  randombytes_buf,
  ready,
  to_base64
} from "libsodium-wrappers"
import { JayZ, JayZProps } from "../main/JayZ"
import { FixedKeyProvider } from "../main/key-providers"
import {
  DecryptDataKeyResult,
  GenerateDataKeyResult,
  KeyProvider
} from "../main/key-providers/DataKeyProvider"
import { aBankAccount, BankAccount } from "./util"

describe("JayZ", () => {
  beforeAll(async () => await ready)

  const fieldsToEncrypt: (keyof BankAccount)[] = [
    "accountNumber",
    "balance",
    "routingNumber",
    "notes"
  ]

  it("should encrypt an item", async () => {
    const { jayz, bankAccount } = setup()
    const encryptedItem = await jayz.encryptItem({
      item: bankAccount,
      fieldsToEncrypt
    })

    expect(encryptedItem.pk).toEqual("account-123")
    expect(encryptedItem.sk).toEqual("Flava Flav")
    expect(encryptedItem.accountNumber).not.toEqual("123")
    expect(encryptedItem.routingNumber).not.toEqual("456")
    expect(encryptedItem.balance).not.toEqual(100)
    expect(encryptedItem.notes).not.toEqual({
      previousBalances: [0, 50]
    })
  })

  it("should decrypt an item", async () => {
    const { jayz, bankAccount } = setup()

    const encryptedItem = await jayz.encryptItem({
      item: bankAccount,
      fieldsToEncrypt
    })

    const decryptedItem = await jayz.decryptItem(encryptedItem)
    expect(decryptedItem).toEqual(bankAccount)
  })

  it("should not reuse data keys by default when encryptItems invoked with multiple items", async () => {
    const keyProvider = new CountingKeyProvider()
    const { jayz, bankAccount } = setup({
      keyProvider
    })

    expect(keyProvider.keysIssued).toEqual(0)
    await jayz.encryptItems([
      { item: bankAccount, fieldsToEncrypt },
      { item: bankAccount, fieldsToEncrypt }
    ])

    expect(keyProvider.keysIssued).toEqual(2)
  })

  it("should not reuse data keys by default when encryptItems invoked multiple times", async () => {
    const keyProvider = new CountingKeyProvider()
    const { jayz, bankAccount } = setup({
      keyProvider
    })

    expect(keyProvider.keysIssued).toEqual(0)
    await jayz.encryptItems([{ item: bankAccount, fieldsToEncrypt }])
    expect(keyProvider.keysIssued).toEqual(1)

    await jayz.encryptItems([{ item: bankAccount, fieldsToEncrypt }])
    expect(keyProvider.keysIssued).toEqual(2)
  })

  it("should reuse data keys when encryptItems invoked once with multiple items", async () => {
    const keyProvider = new CountingKeyProvider()
    const { jayz, bankAccount } = setup({
      keyProvider,
      maxUsesPerDataKey: 2
    })

    const [item1, item2, item3] = await jayz.encryptItems([
      { item: bankAccount, fieldsToEncrypt },
      { item: bankAccount, fieldsToEncrypt },
      { item: bankAccount, fieldsToEncrypt }
    ])

    const [decryptedItem1, decryptedItem2, decryptedItem3] =
      await jayz.decryptItems([item1, item2, item3])

    expect(decryptedItem1).toEqual(bankAccount)
    expect(decryptedItem2).toEqual(bankAccount)
    expect(decryptedItem3).toEqual(bankAccount)
    expect(keyProvider.keysIssued).toEqual(2)
    expect(item1.__jayz__metadata.encryptedDataKey).toEqual(
      item2.__jayz__metadata.encryptedDataKey
    )

    expect(item1.__jayz__metadata.encryptedDataKey).not.toEqual(
      item3.__jayz__metadata.encryptedDataKey
    )
  })

  it("should reuse data keys when encryptItems invoked multiple times", async () => {
    const keyProvider = new CountingKeyProvider()
    const { jayz, bankAccount } = setup({
      keyProvider,
      maxUsesPerDataKey: 2
    })

    const encryptAndDecrypt = async () => {
      const [encryptedItem] = await jayz.encryptItems([
        { item: bankAccount, fieldsToEncrypt }
      ])

      const [decryptedItem] = await jayz.decryptItems([encryptedItem])
      expect(decryptedItem).toEqual(bankAccount)
    }

    await encryptAndDecrypt()
    expect(keyProvider.keysIssued).toEqual(1)

    await encryptAndDecrypt()
    expect(keyProvider.keysIssued).toEqual(1)

    await encryptAndDecrypt()
    expect(keyProvider.keysIssued).toEqual(2)
  })
})

function setup(
  config: JayZProps = {
    keyProvider: new FixedKeyProvider(
      to_base64(randombytes_buf(crypto_kdf_KEYBYTES))
    )
  }
): { bankAccount: BankAccount; jayz: JayZ } {
  const bankAccount = aBankAccount()
  const jayz = new JayZ(config)
  return { jayz, bankAccount }
}

class CountingKeyProvider implements KeyProvider {
  public keysIssued = 0

  async generateDataKey(): Promise<GenerateDataKeyResult> {
    await ready
    const key = randombytes_buf(crypto_kdf_KEYBYTES)
    this.keysIssued += 1
    return {
      encryptedKey: key,
      plaintextKey: key
    }
  }

  async decryptDataKey(
    encryptedDataKey: Uint8Array
  ): Promise<DecryptDataKeyResult> {
    return { plaintextKey: encryptedDataKey.slice(0) }
  }
}
