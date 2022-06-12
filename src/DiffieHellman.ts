import * as crypto from 'crypto'

export class DiffieHellman {
    createDiffieHellman(primeLength: number = 2048): { df: crypto.DiffieHellman, key: Buffer, prime:  any, generator:  any } {
        const df = crypto.createDiffieHellman(primeLength)
        const key = df.generateKeys()
        const prime = df.getPrime()
        const generator = df.getGenerator()
        return { df, key, prime, generator }
    }

    getDiffieHellman(prime: number, generator: number): { df: crypto.DiffieHellman, key: Buffer, prime:  any, generator:  any }  {
        const df = crypto.createDiffieHellman(prime, generator)
        const key = df.generateKeys()
        return { df, key, prime, generator }
    }  
}