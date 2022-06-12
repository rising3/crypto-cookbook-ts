import { RsaCipher } from '../src/RsaCipher'
import { CryptoUtils } from '../src/CryptoUtils'

describe('RsaCipher', () => {
    const cipher = new RsaCipher()
    const src = Buffer.from('some data to sign')
    const publicRaw = Buffer.from('305c300d06092a864886f70d0101010500034b003048024100e5ed3a74b36ab8ac4b3af53bda58678154d6439f3e430f797238f269b4e021c472407ee76e5967e0784234bee129ae12593814d9260000d80d4a5cdc6a5c9a270203010001', 'hex')
    const publicKey = CryptoUtils.restorePublicKey(CryptoUtils.publicKeyToPem(publicRaw))
    const privateRaw = Buffer.from('30820154020100300d06092a864886f70d01010105000482013e3082013a020100024100e5ed3a74b36ab8ac4b3af53bda58678154d6439f3e430f797238f269b4e021c472407ee76e5967e0784234bee129ae12593814d9260000d80d4a5cdc6a5c9a270203010001024100ba2ba8be5f9c1525e4d03b4b1853a69370e700e00ae0efc1ad3bf104a86126d4c9a58779f3b17e3ca48c9231a9582d5c13c1bca1174845e93279610302e42c49022100f5b7b3c12198e0a90ba9d27ee7f20f0bbfff73815d67ded41294acc79c1545f5022100ef8c5ce8688d5cbf6e5d5ea5218dc507b8d5e78bea42d7f868abe0b2caa0322b02201ca8dc927e34b29f84f8bdd0878538340aa4e4f805c903b880a24eb4c983c1b102205dc4fe2163bbe250752d4b7d2c73486b4b6940283edd47994fafe8575485fcdd0220381373cfb1b6923a8516c23c558352b6f39204f47d1be3716eb0bc42d49edf69', 'hex')
    const privateKey = CryptoUtils.restorePrivateKey(CryptoUtils.privateKeyToPem(privateRaw))

    it('rsa encrypt', () => {
        const actual = cipher.encrypt(src, publicKey)

        expect(cipher.decrypt(actual, privateKey)).toStrictEqual(src)
    })

    it('rsa decrypt', () => {
        const encrypted = Buffer.from('bfea22e1289ea935d0d176a2ac023ee8bf7ec6bc4513cb19fda45d5a0db1bb8b6f06035167ad3015cd904d1dbe7c2d5a7b77c4ce1cbdcf1066f1d466cbc2ea2d', 'hex')
        const actual = cipher.decrypt(encrypted, privateKey)

        expect(actual).toStrictEqual(src)
    })
})
