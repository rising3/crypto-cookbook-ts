import { AesCipher } from '../src/AesCipher'

describe('AesCipher', () => {
    const cipher = new AesCipher()
    const src = Buffer.from('some data to sign')
    const secret = Buffer.from('f6cebb777b6cd0a54b309c43f9a203f1bf93c516623366a7e748e29f13e940a7', 'hex')
    const iv = Buffer.from('b0eedeeb3ea638c2fec13df196d27d4e', 'hex')
    const add = Buffer.from('/*** Authenticated Data ***/')

    it('cbc encrypt', () => {
        const encrypted = Buffer.from('10000000b0eedeeb3ea638c2fec13df196d27d4e7598acc645cffcfcb9a8ded5c71ab074ee331fd247b6440859219b3762700174', 'hex')
        const actual = cipher.encrypt(src, secret, iv)

        expect(actual).toStrictEqual(encrypted)
    })

    it('cbc decrypt', () => {
        const encrypted = Buffer.from('10000000b0eedeeb3ea638c2fec13df196d27d4e7598acc645cffcfcb9a8ded5c71ab074ee331fd247b6440859219b3762700174', 'hex')
        const actual = cipher.decrypt(encrypted, secret)

        expect(actual).toStrictEqual(src)
    })

    it('gcm encrypt', () => {
        const encrypted = Buffer.from('10000000b0eedeeb3ea638c2fec13df196d27d4e100000007596801d81715173d802291ef018fb4629ac0a1a1c3b056f99bf339a6922be475b', 'hex')
        const actual = cipher.gcmEncrypt(src, secret, iv)

        expect(actual).toStrictEqual(encrypted)
    })

    it('gcm decrypt', () => {
        const encrypted = Buffer.from('10000000b0eedeeb3ea638c2fec13df196d27d4e100000007596801d81715173d802291ef018fb4629ac0a1a1c3b056f99bf339a6922be475b', 'hex')
        const actual = cipher.gcmDecrypt(encrypted, secret)

        expect(src).toStrictEqual(actual)
    })

    it('gcm encrypt with add', () => {
        const encrypted = Buffer.from('10000000b0eedeeb3ea638c2fec13df196d27d4e10000000a456fc2582bd8967b9c0a48bd6042d2329ac0a1a1c3b056f99bf339a6922be475b', 'hex')
        const actual = cipher.gcmEncrypt(src, secret, iv, add)

        expect(actual).toStrictEqual(encrypted)
    })

    it('gcm decrypt with add', () => {
        const encrypted = Buffer.from('10000000b0eedeeb3ea638c2fec13df196d27d4e10000000a456fc2582bd8967b9c0a48bd6042d2329ac0a1a1c3b056f99bf339a6922be475b', 'hex')
        const actual = cipher.gcmDecrypt(encrypted, secret, add)

        expect(actual).toStrictEqual(src)
    })
})
