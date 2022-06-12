import * as crypto from 'crypto'

export class Hmac {
    private readonly defaultAlgorithm = "sha256"

    mac(src: Buffer, key: crypto.CipherKey, algorithm: string = this.defaultAlgorithm): Buffer {
        const hmac = crypto.createHmac(algorithm, key)
        return hmac.update(src).digest()
    }
    
    verify(originalMac: Buffer, src: Buffer, key: crypto.CipherKey, algorithm: string = this.defaultAlgorithm): boolean {
        const hmac = crypto.createHmac(algorithm, key)
        return originalMac.equals(hmac.update(src).digest())
    }
}
