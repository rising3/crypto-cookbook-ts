import * as crypto from 'crypto'
import { CryptoUtils } from './CryptoUtils'

export class Pbkdf2Digest {
    private readonly defaultIterations = 100000
    private readonly defaultKeyLen = 256
    private readonly defaultAlgorithm = 'sha256'


    hash(password: string, salt: Buffer, iterations: number =  this.defaultIterations, keyLen: number = this.defaultKeyLen, algorithm: string = this.defaultAlgorithm): Buffer {
        const hash = crypto.pbkdf2Sync(password, salt, iterations, keyLen, algorithm)
        const sb = CryptoUtils.serialize(salt)
        const ib = CryptoUtils.int32ToBuffer(iterations)
        const kb = CryptoUtils.int32ToBuffer(keyLen)

        return  Buffer.concat([ib, kb, sb, hash])
    } 

    verify(originalHash: Buffer, password: string, algorithm: string = this.defaultAlgorithm): boolean {
        let pos = 0
        const iterations = originalHash.readInt32LE()
        pos += Int32Array.BYTES_PER_ELEMENT
        const keyLen = originalHash.readInt32LE(pos)
        pos += Int32Array.BYTES_PER_ELEMENT
        const salt = CryptoUtils.deserialize(originalHash.subarray(pos)).values
         return originalHash.equals(this.hash(password, salt, iterations, keyLen, algorithm))
    } 
}
