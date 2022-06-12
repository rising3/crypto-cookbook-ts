import * as crypto from 'crypto'
import * as assert from 'assert'

export class CryptoUtils {

    static generateBytes(size: number = 8): Buffer {
        return crypto.randomBytes(size)
    }

    static generateKey(size: number = 128, algorithm: 'aes' | 'hmac' = 'aes'): crypto.KeyObject {
        return crypto.generateKeySync(algorithm, { length: size })
    }

    static generateHmacKey(size: number = 128): crypto.KeyObject {
        return this.generateKey(Math.floor(size) * 8, 'hmac')
    }

    static generateKeyPair(length: number = 2048, format: crypto.KeyFormat = 'pem', passphrase?: string): crypto.KeyPairSyncResult<any, any> {
        const options = format === 'der' ? this.createRsaDerOptions(length) : this.createRsaPemOptions(length)
        if (passphrase) {
            options.privateKeyEncoding.cipher = 'aes-256-cbc'
            options.privateKeyEncoding.passphrase = passphrase
        }
        return crypto.generateKeyPairSync('rsa', options)
    }

    static restoreKey(key: DataView | Buffer): crypto.KeyObject {
        return crypto.createSecretKey(key)
    }

    static restorePublicKey(key: string | Buffer | crypto.KeyObject | crypto.PublicKeyInput | crypto.JsonWebKeyInput): crypto.KeyObject {
        return crypto.createPublicKey(key)
    }

    static restorePrivateKey(key: string | Buffer | crypto.JsonWebKeyInput | crypto.PrivateKeyInput): crypto.KeyObject {
        return crypto.createPrivateKey(key)
    }

    static publicKeyToPem(key: Buffer | DataView): string {
        const sb = this.chunkString(key.toString('base64'), 64)
        sb.unshift('-----BEGIN PUBLIC KEY-----')
        sb.push('-----END PUBLIC KEY-----')
        return sb.join('\n')
    }

    static privateKeyToPem(key: Buffer | DataView, encrypted: boolean = false): string {
        const sb = this.chunkString(key.toString('base64'), 64)
        sb.unshift(encrypted ? '-----BEGIN ENCRYPTED PRIVATE KEY-----' : '-----BEGIN PRIVATE KEY-----')
        sb.push(encrypted ? '-----END ENCRYPTED PRIVATE KEY-----' : '-----END PRIVATE KEY-----')
        return sb.join('\n')
    }

    static pemToByteArray(key: string): Buffer {
        const regexPem = /-----BEGIN .*-----(\n|\r|\r\n)([0-9a-zA-Z\+\/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+\/=]{1,63}(\n|\r|\r\n))?-----END .*-----(\n|\r|\r\n)?/
        assert(regexPem.test(key))

        return Buffer.from(key.replace(/-----.*-----/g, '').replace(/\n|\r|\r\n/g, ''), 'base64')
    }

    static serialize(data: Buffer): Buffer {
        return Buffer.concat([this.int32ToBuffer(data.length, true), data])
    }

    static deserialize(data: Buffer): { values: Buffer, others: Buffer } {
        let pos = 0
        const size = data.readInt32LE()
        pos += Int32Array.BYTES_PER_ELEMENT
        const values = data.subarray(pos, pos + size)
        pos += size
        const others = data.subarray(pos)
        return { values, others }
    }

    static int32ToBuffer(value: number, littleEndian?: boolean): Buffer {
        const buf = new ArrayBuffer(Int32Array.BYTES_PER_ELEMENT)
        new DataView(buf).setInt32(0, value, littleEndian !== undefined ? littleEndian : true)
        return Buffer.from(buf)
    }

    private static createRsaPemOptions(length: number): crypto.RSAKeyPairOptions<'pem', 'pem'> {
        return {
            modulusLength: length,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        }
    }

    private static createRsaDerOptions(length: number): crypto.RSAKeyPairOptions<'der', 'der'> {
        return {
            modulusLength: length,
            publicKeyEncoding: {
                type: 'spki',
                format: 'der'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'der'
            }
        }
    }

    private static chunkString(v: string, length: number): string[] {
        const sb: string[] = []
        let wk = v
        while (wk.length > 0) {
            sb.push(wk.substring(0, length))
            wk = wk.substring(length)
        }
        return sb
    }
}