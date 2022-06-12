import * as crypto from 'crypto'

export class Digest {
    private readonly defaultAlgorithm = "sha256"

    hash(src: Buffer, algorithm: string = this.defaultAlgorithm): Buffer {
        const md = crypto.createHash(algorithm)
        return md.update(src).end().digest()
    } 

    verify(originalHash: Buffer, src: Buffer, algorithm: string = this.defaultAlgorithm): boolean {
        return originalHash.equals(this.hash(src, algorithm))
    } 
}
