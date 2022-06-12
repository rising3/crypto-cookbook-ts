import * as crypto from 'crypto'
import { CryptoUtils } from "./CryptoUtils"

export class AesCipher {
    private readonly algoAesCbc = 'aes-256-cbc'
    private readonly algoAesGcm: crypto.CipherGCMTypes = 'aes-256-gcm'

    encrypt(src: Buffer, key: crypto.CipherKey, iv: Buffer, algorithm = this.algoAesCbc): Buffer {
        const cipher = crypto.createCipheriv(algorithm, key, iv)
        return Buffer.concat([CryptoUtils.serialize(iv), cipher.update(src), cipher.final()])
    }

    decrypt(src: Buffer, key: crypto.CipherKey, algorithm = this.algoAesCbc): Buffer {
        const iv = CryptoUtils.deserialize(src)
        const cipher = crypto.createDecipheriv(algorithm, key, iv.values)
        return Buffer.concat([cipher.update(iv.others), cipher.final()])
    }

    gcmEncrypt(src: Buffer, key: crypto.CipherKey, iv: Buffer, add?: Buffer, algorithm = this.algoAesGcm): Buffer {
        const cipher = crypto.createCipheriv(algorithm, key, iv) as crypto.CipherGCM
        add && cipher.setAAD(add)
        const encrypted = Buffer.concat([cipher.update(src), cipher.final()])
        const authTag = cipher.getAuthTag()

        return Buffer.concat([CryptoUtils.serialize(iv), CryptoUtils.serialize(authTag), encrypted])
    }

    gcmDecrypt(src: Buffer, key: crypto.CipherKey, add?: Buffer, algorithm = this.algoAesGcm): Buffer {
        const iv = CryptoUtils.deserialize(src)
        const authTag = CryptoUtils.deserialize(iv.others)
        const cipher = crypto.createDecipheriv(algorithm, key, iv.values) as crypto.DecipherGCM
        cipher.setAuthTag(authTag.values)
        add && cipher.setAAD(add)
        return Buffer.concat([cipher.update(authTag.others), cipher.final()])
    }
}
