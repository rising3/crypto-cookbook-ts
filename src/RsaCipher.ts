import * as crypto from 'crypto'

export class RsaCipher {
    encrypt(buffer: Buffer, key: crypto.RsaPublicKey | crypto.KeyLike | crypto.RsaPrivateKey): Buffer {
        return crypto.publicEncrypt(key, buffer)
    }
    
    decrypt(buffer: Buffer, key: crypto.KeyLike | crypto.RsaPrivateKey): Buffer {
        return crypto.privateDecrypt(key, buffer)
    }
}
