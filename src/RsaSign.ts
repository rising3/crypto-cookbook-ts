import * as crypto from 'crypto'

export class RsaSign {
    private readonly defaultAlgorithm = "rsa-sha256"

    sign(src: Buffer, key: crypto.KeyLike | crypto.SignKeyObjectInput | crypto.SignPrivateKeyInput, algorithm: string = this.defaultAlgorithm): Buffer {
        const signer = crypto.createSign(algorithm)
        return signer.update(src).end().sign(key)
    }
    
    verify(sign: Buffer, src: Buffer, key: crypto.KeyLike | crypto.VerifyKeyObjectInput | crypto.VerifyPublicKeyInput, algorithm: string = this.defaultAlgorithm) {
        const verifier = crypto.createVerify(algorithm)
        return verifier.update(src).end().verify(key, sign)
    }  
}
