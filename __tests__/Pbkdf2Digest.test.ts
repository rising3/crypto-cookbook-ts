import { CryptoUtils } from '../src/CryptoUtils'
import { Pbkdf2Digest } from '../src/Pbkdf2Digest'

describe('Hash', () => {
    const digest = new Pbkdf2Digest()
    const password = 'password'
    const salt = CryptoUtils.generateBytes(16)
    const iterations = 10000
    const keyLen = 256

    it('sha1', () => {
        const actual = digest.hash(password, salt, iterations, keyLen, 'sha1')

        expect(digest.verify(actual, password, 'sha1')).toBeTruthy()
    })

    it('sha256', () => {
        const actual = digest.hash(password, salt, iterations, keyLen, 'sha256')

        expect(digest.verify(actual, password, 'sha256')).toBeTruthy()
    })

    it('sha384', () => {
        const actual = digest.hash(password, salt, iterations, keyLen, 'sha384')

        expect(digest.verify(actual, password, 'sha384')).toBeTruthy()
    })

    it('sha512', () => {
        const actual = digest.hash(password, salt, iterations, keyLen, 'sha512')

        expect(digest.verify(actual, password, 'sha512')).toBeTruthy()
    })
})
