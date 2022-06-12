import { Digest } from './Digest'
import { Pbkdf2Digest } from './Pbkdf2Digest'
import { AesCipher } from './AesCipher'
import { Hmac } from './Hmac'
import { RsaCipher } from './RsaCipher'
import { RsaSign } from './RsaSign'
import { DiffieHellman } from './DiffieHellman'
import { CryptoUtils } from './CryptoUtils'

const TEXT = 'some data to sign'

function hashExample() {
    const algorithms = ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
    const digest = new Digest()
    console.log('=== hash example ===')
    console.log(`plain text: ${TEXT}`)
    algorithms.forEach(algorithm => {
        const hash = digest.hash(Buffer.from(TEXT), algorithm)
        const verify = digest.verify(hash, Buffer.from(TEXT), algorithm)
        console.log(`  ${algorithm}`)
        console.log(`    hash: ${hash.toString('hex')}`)
        console.log(`    verify: ${verify}`)
    })
}

function pbkdf2Example() {
    const digest = new Pbkdf2Digest()
    const password = 'P@ssW0rd'
    const salt = CryptoUtils.generateBytes(16)
    const iterations = 10000
    const keyLen = 256
    const hash = digest.hash(password, salt, iterations, keyLen)
    const verify = digest.verify(hash, password)
    console.log('=== pbkdf2 example ===')
    console.log(`password: ${password}`)
    console.log(`salt: ${salt.toString('hex')}`)
    console.log(`hash: ${hash.toString('hex')}`)
    console.log(`verify: ${verify}`)
}

function cbcCipherExample() {
    const cipher = new AesCipher()
    const key = CryptoUtils.generateKey(256)
    const iv = CryptoUtils.generateBytes(16)
    const enc = cipher.encrypt(Buffer.from(TEXT), key, iv)
    const dec = cipher.decrypt(enc, key)
    console.log('=== cipher(CBC) example ===')
    console.log(`plain text: ${TEXT}`)
    console.log(`  key      : ${key.export().toString('hex')}`)
    console.log(`  iv       : ${iv.toString('hex')}`)
    console.log(`  encrypted: ${enc.toString('hex')}`)
    console.log(`  decrypted: ${String(dec)}`)
}
function gcmCipherExample() {
    const cipher = new AesCipher()
    const key = CryptoUtils.generateKey(256)
    const iv = CryptoUtils.generateBytes(16)
    const add = Buffer.from('Authenticated Data')
    const enc = cipher.gcmEncrypt(Buffer.from(TEXT), key, iv, add)
    const dec = cipher.gcmDecrypt(enc, key, add)
    console.log('=== cipher(GCM) example ===')
    console.log(`plain text: ${TEXT}`)
    console.log(`  key      : ${key.export().toString('hex')}`)
    console.log(`  iv       : ${iv.toString('hex')}`)
    console.log(`  add      : ${add}`)
    console.log(`  encrypted: ${enc.toString('hex')}`)
    console.log(`  decrypted: ${String(dec)}`)
}

function hmacExample() {
    const algorithms = ['md5', 'sha1', 'sha256', 'sha384', 'sha512']
    const hmac = new Hmac()
    const key = CryptoUtils.generateHmacKey()
    console.log('=== hmac example ===')
    console.log(`plain text: ${TEXT}`)
    algorithms.forEach(algorithm => {
        const mac = hmac.mac(Buffer.from(TEXT), key, algorithm)
        const verify = hmac.verify(mac, Buffer.from(TEXT), key, algorithm)
        console.log(`  ${algorithm}`)
        console.log(`    hash: ${mac.toString('hex')}`)
        console.log(`    verify: ${verify}`)
    })
}

function rsaCipherExample() {
    const cipher = new RsaCipher()
    const pem = CryptoUtils.generateKeyPair(512)
    const encrypted = cipher.encrypt(Buffer.from(TEXT), pem.publicKey)
    const decrypted = cipher.decrypt(encrypted, pem.privateKey)
    console.log('=== rsa encryption examples ===')
    console.log(`PEM - public :\n${pem.publicKey}`)
    console.log(`PEM - private:\n${pem.privateKey}`)
    console.log(`plain text: ${TEXT}`)
    console.log('public encrypt -> private decrypt:')
    console.log(`  encrypted: ${encrypted.toString('hex')}`)
    console.log(`  decrypted: ${decrypted.toString()}`)
}

function rsaSignExample() {
    const sign = new RsaSign()
    const pem = CryptoUtils.generateKeyPair(512)
    const signed = sign.sign(Buffer.from(TEXT), pem.privateKey)
    const verify = sign.verify(signed, Buffer.from(TEXT), pem.publicKey)
    console.log('=== rsa sign/vrifiy example ===')
    console.log(`plain text: ${TEXT}`)
    console.log(`  signed: ${signed.toString('hex')}`)
    console.log(`  verify: ${verify}`)
}

function dhExample() {
    const dh = new DiffieHellman()
    const alice = dh.createDiffieHellman(512)
    const bob = dh.getDiffieHellman(alice.prime, alice.generator)
    const aliceSecret = alice.df.computeSecret(bob.key)
    const bobSecret = bob.df.computeSecret(alice.key)
    console.log('=== Diffie Hellman example ===')
    console.log('alice...')
    console.log(`  key: ${alice.key.toString('hex')}`)
    console.log(`  prime: ${alice.prime.toString('hex')}`)
    console.log(`  generator: ${alice.generator.toString('hex')}`)
    console.log('bob...')
    console.log(`  key: ${bob.key.toString('hex')}`)
    console.log(`exchange and generate the secrets...`)
    console.log(`  alice secret: ${aliceSecret.toString('hex')}`)
    console.log(`  bob   secret: ${bobSecret.toString('hex')}`)
    console.log(`  compare secrets: ${aliceSecret.equals(bobSecret)}`)
}

function main() {
    hashExample()
    console.log()

    pbkdf2Example()
    console.log()

    cbcCipherExample()
    console.log()

    gcmCipherExample()
    console.log()

    hmacExample()
    console.log()

    rsaCipherExample()
    console.log()

    rsaSignExample()
    console.log()

    dhExample()
}

main()
