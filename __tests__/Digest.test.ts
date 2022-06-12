import { Digest } from '../src/Digest'

describe('Hash', () => {
    const digest = new Digest()
    const src = Buffer.from('some data to sign')

    it('md5', () => {
        const actual = digest.hash(src, 'md5')

        expect(digest.verify(actual, src, 'md5')).toBeTruthy()
    })

    it('sha1', () => {
        const actual = digest.hash(src, 'sha1')

        expect(digest.verify(actual, src, 'sha1')).toBeTruthy()
    })

    it('sha256', () => {
        const actual = digest.hash(src, 'sha256')

        expect(digest.verify(actual, src, 'sha256')).toBeTruthy()
    })

    it('sha384', () => {
        const actual = digest.hash(src, 'sha384')

        expect(digest.verify(actual, src, 'sha384')).toBeTruthy()
    })

    it('sha512', () => {
        const actual = digest.hash(src, 'sha512')

        expect(digest.verify(actual, src, 'sha512')).toBeTruthy()
    })
})
