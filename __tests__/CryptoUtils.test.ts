import { CryptoUtils } from '../src/CryptoUtils'

describe('CryptoUtils', () => {
    it('generateBytes', () => {
        const actual = CryptoUtils.generateBytes()

        expect(actual.length).toStrictEqual(8)
    })

    it('generateKey', () => {
        const actual = CryptoUtils.generateKey()

        expect(actual.symmetricKeySize).toStrictEqual(16)
        expect(actual.type).toStrictEqual('secret')
    })

    it('generateHmacKey', () => {
        const actual = CryptoUtils.generateHmacKey()

        expect(actual.symmetricKeySize).toStrictEqual(128)
        expect(actual.type).toStrictEqual('secret')
    })

    it('restoreKey', () => {
        const actual = CryptoUtils.restoreKey(Buffer.from('88909280da6ad56583ebcdb6d4957401', 'hex'))

        expect(actual.symmetricKeySize).toStrictEqual(16)
        expect(actual.type).toStrictEqual('secret')
    })

    it('restorePublicKey', () => {
        const publicRaw = Buffer.from('305c300d06092a864886f70d0101010500034b003048024100e5ed3a74b36ab8ac4b3af53bda58678154d6439f3e430f797238f269b4e021c472407ee76e5967e0784234bee129ae12593814d9260000d80d4a5cdc6a5c9a270203010001', 'hex')
        const actual = CryptoUtils.restorePublicKey(CryptoUtils.publicKeyToPem(publicRaw))

        expect(actual.type).toStrictEqual('public')
        expect(actual.export({ type: 'spki', format: 'der' })).toStrictEqual(publicRaw)
    })

    it('restorePrivateKey', () => {
        const privateRaw = Buffer.from('30820154020100300d06092a864886f70d01010105000482013e3082013a020100024100e5ed3a74b36ab8ac4b3af53bda58678154d6439f3e430f797238f269b4e021c472407ee76e5967e0784234bee129ae12593814d9260000d80d4a5cdc6a5c9a270203010001024100ba2ba8be5f9c1525e4d03b4b1853a69370e700e00ae0efc1ad3bf104a86126d4c9a58779f3b17e3ca48c9231a9582d5c13c1bca1174845e93279610302e42c49022100f5b7b3c12198e0a90ba9d27ee7f20f0bbfff73815d67ded41294acc79c1545f5022100ef8c5ce8688d5cbf6e5d5ea5218dc507b8d5e78bea42d7f868abe0b2caa0322b02201ca8dc927e34b29f84f8bdd0878538340aa4e4f805c903b880a24eb4c983c1b102205dc4fe2163bbe250752d4b7d2c73486b4b6940283edd47994fafe8575485fcdd0220381373cfb1b6923a8516c23c558352b6f39204f47d1be3716eb0bc42d49edf69', 'hex')
        const actual = CryptoUtils.restorePrivateKey(CryptoUtils.privateKeyToPem(privateRaw))

        expect(actual.type).toStrictEqual('private')
        expect(actual.export({ type: 'pkcs8', format: 'der' })).toStrictEqual(privateRaw)
    })

    it('publicKeyToPem', () => {
        const publicRaw = Buffer.from('305c300d06092a864886f70d0101010500034b003048024100e5ed3a74b36ab8ac4b3af53bda58678154d6439f3e430f797238f269b4e021c472407ee76e5967e0784234bee129ae12593814d9260000d80d4a5cdc6a5c9a270203010001', 'hex')
        const actual = CryptoUtils.publicKeyToPem(publicRaw)

        expect(assertPublicKey(actual)).toBeTruthy()
    })

    it('privateKeyToPem', () => {
        const privateRaw = Buffer.from('30820154020100300d06092a864886f70d01010105000482013e3082013a020100024100e5ed3a74b36ab8ac4b3af53bda58678154d6439f3e430f797238f269b4e021c472407ee76e5967e0784234bee129ae12593814d9260000d80d4a5cdc6a5c9a270203010001024100ba2ba8be5f9c1525e4d03b4b1853a69370e700e00ae0efc1ad3bf104a86126d4c9a58779f3b17e3ca48c9231a9582d5c13c1bca1174845e93279610302e42c49022100f5b7b3c12198e0a90ba9d27ee7f20f0bbfff73815d67ded41294acc79c1545f5022100ef8c5ce8688d5cbf6e5d5ea5218dc507b8d5e78bea42d7f868abe0b2caa0322b02201ca8dc927e34b29f84f8bdd0878538340aa4e4f805c903b880a24eb4c983c1b102205dc4fe2163bbe250752d4b7d2c73486b4b6940283edd47994fafe8575485fcdd0220381373cfb1b6923a8516c23c558352b6f39204f47d1be3716eb0bc42d49edf69', 'hex')
        const actual = CryptoUtils.privateKeyToPem(privateRaw)

        expect(assertPrivateKey(actual)).toBeTruthy()
    })

    it('pemToByteArray', () => {
        const publicRaw = Buffer.from('305c300d06092a864886f70d0101010500034b003048024100e5ed3a74b36ab8ac4b3af53bda58678154d6439f3e430f797238f269b4e021c472407ee76e5967e0784234bee129ae12593814d9260000d80d4a5cdc6a5c9a270203010001', 'hex')
        const pem = CryptoUtils.publicKeyToPem(publicRaw)
        const actual = CryptoUtils.pemToByteArray(pem)

        expect(actual).toStrictEqual(publicRaw)
    })

    it('generateKeyPair with pem', () => {
        const actual = CryptoUtils.generateKeyPair(512)

        expect(assertPublicKey(actual.publicKey)).toBeTruthy()
        expect(assertPrivateKey(actual.privateKey)).toBeTruthy()
    })

    it('generateKeyPair with der', () => {
        const actual = CryptoUtils.generateKeyPair(512, 'der')

        expect(actual.publicKey instanceof Buffer).toBeTruthy()
        expect(actual.privateKey instanceof Buffer).toBeTruthy()
    })

    it('generateKeyPair with pass', () => {
        const actual = CryptoUtils.generateKeyPair(512, 'pem', 'password')

        expect(assertPublicKey(actual.publicKey)).toBeTruthy()
        expect(assertPrivateKey(actual.privateKey)).toBeTruthy()
    })

    it('generateKeyPair with pass', () => {
        const actual = CryptoUtils.generateKeyPair(512, 'pem', 'password')

        expect(assertPublicKey(actual.publicKey)).toBeTruthy()
        expect(assertPrivateKey(actual.privateKey)).toBeTruthy()
    })

    it('serialize', () => {
        const actual = CryptoUtils.serialize(Buffer.from('Hello'))

        expect(actual.length).toBe(9)
        expect(actual).toStrictEqual(Buffer.from('0500000048656c6c6f', 'hex'))
    })

    it('deserialize', () => {
         const actual = CryptoUtils.deserialize(Buffer.concat([Buffer.from('0500000048656c6c6f', 'hex'), Buffer.from('Hello')]))

        expect(actual.values).toStrictEqual(Buffer.from('Hello'))
        expect(actual.others.length).toBe(5)
        expect(actual.others).toStrictEqual(Buffer.from('Hello'))
    })

    it('int32ToBuffer by little endian', () => {
        const actual = CryptoUtils.int32ToBuffer(123, true)

        expect(actual).toStrictEqual(Buffer.from('7b000000', 'hex'))
        expect(actual.readInt32LE()).toStrictEqual(123)
    })

    it('int32ToBuffer by big endian', () => {
        const actual = CryptoUtils.int32ToBuffer(123, false)

        expect(actual).toStrictEqual(Buffer.from('0000007b', 'hex'))
        expect(actual.readInt32BE()).toStrictEqual(123)
    })

    function assertPublicKey(pem: string): boolean {
        const regexPem = /-----BEGIN PUBLIC.*-----(\n|\r|\r\n)([0-9a-zA-Z\+\/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+\/=]{1,63}(\n|\r|\r\n))?-----END PUBLIC.*-----(\n|\r|\r\n)?/
        return regexPem.test(pem)
    }

    function assertPrivateKey(pem: string): boolean {
        const regexPem = /-----BEGIN PRIVATE.*-----|-----BEGIN ENCRYPTED PRIVATE.*-----(\n|\r|\r\n)([0-9a-zA-Z\+\/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+\/=]{1,63}(\n|\r|\r\n))?-----END PRIVATE.*-----|-----END ENCRYPTED PRIVATE.*-----(\n|\r|\r\n)?/
        return regexPem.test(pem)
    }
})
