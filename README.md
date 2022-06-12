# crypto cookbook for TypeScript
[![Build](https://github.com/rising3/crypto-cookbook-ts/actions/workflows/build.yml/badge.svg)](https://github.com/rising3/crypto-cookbook-ts/actions/workflows/build.yml)

How to use node:crypto module for Node.js.

Prerequisites:
* Node.js 16 or higher
* TypeScript 4.6 or higher

## Examples for crypto module

### Hash

Creating hash digests of data.

Using the following:
* crypto.createHash()

```
=== hash example ===
plain text: some data to sign
  md5
    hash: edfabb69817093b81e8506b24e960716
    verify: true
  sha1
    hash: 650a9c3d72ba9afc1be522facf16d876f339a536
    verify: true
  sha256
    hash: a86df237ac3d15e22d93a08358ae3a7a78787ee59fc8246c05783f7c56e6c4a0
    verify: true
  sha384
    hash: f8be04ffc0b93153bfdeb03b6845a62e05dbabae0acfbf30ed96d8a552caac892c4d71bab4bbd74d6f0cbf1a413b3a73
    verify: true
  sha512
    hash: 221330694980887c912aa2215b6c6405e71189100cd9fe19910c1a2f9bf7d486eaa2ee410d6f863f15b28c892f8d78726ea1ce07afabdc4d91cd61b37a4d30a8
    verify: true
  ```
### PBKDF2

Creating hash digests of password.

Using the following:
* crypto.pbkdf2Sync()

```
=== pbkdf2 example ===
password: P@ssW0rd
salt: ac08a46e084dfa56659fe7f71fcb23b9
hash: 102700000001000010000000ac08a46e084dfa56659fe7f71fcb23b996aeaa56b2784c1d20146535e5d2fcf7a39f685c6d7450a851c83f05145fa6dcebab693f1b58b32316013f3010e7b8c27c9430c0af28d90f20d835d9572ba879854ded958300016802af82c3877997b49c5a636e2c24b787c72ccc4e75f73e32cc59cac314362e90baaafd5219431af4e16fcda0e92cee07c3b41ce2ebb23b803e9afacd093402bad7e26efbb2c1365cba51a3ace9ec7a687e2f627e7646bd1e035d838b818022b8adfdadeef6ce456bf6af14fbdd850ab731784892018f5e8b7dd1aa474afb9c418cef820c218f48d1af6275144e8b80c8807addcb62158c6edc832e18fb79e5a102077fab1a694a0a38a352b38399fd82180fad908be888d1
verify: true
```

### AES Cipher

Encrypt and decrypt data.

Using the following:
* crypto.generateKeySync()
* crypto.randomBytes()
* crypto.createCipheriv()
* crypto.createDecipheriv()

```
=== cipher(CBC) example ===
plain text: some data to sign
  key      : 73556b7e486cc48f2b22fc3c8c17c6b1625e386f1fdef06a1cfbd2b49b44b270
  iv       : e1f4df07d0591618b047ac485245dfd0
  encrypted: 10000000e1f4df07d0591618b047ac485245dfd004095dc793689e2c29a0ce97c0424e365d59affb7daa7adfca8a72521ae20d59
  decrypted: some data to sign

=== cipher(GCM) example ===
plain text: some data to sign
  key      : f53f5b55e699ca832716c8836e24a7dc4022a3a50ffa7a23a1176d9b1fd527d1
  iv       : 29d810706fbb557b9e642f1335b45f0e
  add      : Authenticated Data
  encrypted: 1000000029d810706fbb557b9e642f1335b45f0e10000000c4a3aba8b34fb55f169d107028f905e1716d8f9b6e70164ffca27a78de6c80bf74
  decrypted: some data to sign
```

### HMAC

Creating cryptographic HMAC digests.

Using the following:
* crypto.generateKeySync()
* crypto.createHmac()

```                                          
=== hmac example ===
plain text: some data to sign
  md5
    hash: 989a24043e09c0ff38386139610c7353
    verify: true
  sha1
    hash: 8d3077742980f06604b7ea9531155f3e950e5b4b
    verify: true
  sha256
    hash: ed9ff1b0d5feaed22c1a171749c1f32041dc0b677a6a3f4b03ec471a11af25ab
    verify: true
  sha384
    hash: 7d59ac34a5f54147b83debc6cb59d26358c11ad8901f8d24172b917cfad58d1f77bc77c206cfa83656add0f6103c0ddd
    verify: true
  sha512
    hash: 5419ec99904090ffcabd7e4fedfd947b24a1ca81c623c721d97f8745872db034da9f7135e558405c88dcc61b4a5ed32677e94f078500c4cfabce3d278365a676
    verify: true
``` 

### RSA Cipher

Encrypt and decrypt data, using RSA key pair.

Using the following:
* crypto.generateKeyPair()
* crypto.publicEncrypt()
* crypto.privateDecrypt()

``` 
=== rsa encryption examples ===
PEM - public :
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAN1g65US9o9gredOxOasn2zDUXO+uFEt
UNCol6P0JpAO1p01PsdSgyTLPd7Rj94IRrIKhkAo6LbaObjPbgl/NjECAwEAAQ==
-----END PUBLIC KEY-----

PEM - private:
-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA3WDrlRL2j2Ct507E
5qyfbMNRc764US1Q0KiXo/QmkA7WnTU+x1KDJMs93tGP3ghGsgqGQCjotto5uM9u
CX82MQIDAQABAkB5WgiptjRsEg4iLr6myFe4EjVTImf9L78OMmy1lj+RVVusK4J7
zl3cR/6YlmDdiQ0Hn61/jy5pmAcD8O1c7QsFAiEA+ZRrIZxUZup6UG+eAzpV1BBW
CMBpV2msH0dFE+oR92sCIQDjEskyeOitgdcjfNyscXWscJLa1xm/LEFKBhTXxMgb
0wIgDCbs3HMXLPenwvjcUb3qZevxtHVh666qgc9fjqur+kcCIEHbDe0Mcfb4RCvv
p5R/p3AmigDcB4SRUjIkx2C4moyvAiEA3nBrxHkcONwX0e8JSQf+O9GL5LfzatQr
uGtg0AjBzO8=
-----END PRIVATE KEY-----

plain text: some data to sign
public encrypt -> private decrypt:
  encrypted: 0717945cf746b841753ee01305895fda1101c8ed63a0fbbad3c354f89b37af815872278b83b0b24ecddf3047ac0ec48cdcec4c72ce4c4d69d8de71eeecabffba
  decrypted: some data to sign
``` 

### RSA Sign/Verify

Generating and verifying signatures. 

Using the following:
* crypto.generateKeyPair()
* crypto.createSign()
* crypto.createVerify()

``` 
=== rsa sign/vrifiy example ===
plain text: some data to sign
  signed: 20633baf388c053f86ca6fbf4459535fa0c20ba4e2cf36b5e0706b76595d5a7c28e9ef3665bd48d3a1fbc1a9cd46ab27b0a127e304bf11a4ca2b0b0921ec6ad8
  verify: true
```

### Diffie Hellman

Creating Diffie-Hellman key exchanges.

Using the following:
* crypto.createDiffieHellman()

```
=== Diffie Hellman example ===
alice...
  key: 79172d9a6c4bdd68e19bad1c3a55e71bae728259828e35a15be76edaf73fcf6ef150a53c7266d95e815176406b8b75d959da2b56302b9adc8a8ba5c42f6ee922
  prime: 946d4ffa99fc6ecdb91582e77a42597725baec82fd918a7f80e8ef63f99a4519735436f87312ec59c5c42cd2d299aadd8c7661d0c0e5d658b3d690a3be93e867
  generator: 02
bob...
  key: 2b9f63522bb40ec3e4709bde1bf4c0ffdcee721d6c3843b1bb72459367c5a835775cfac73c27613491656e682a290a8ef95f3291d80be2c6f5d77713fbc127af
exchange and generate the secrets...
  alice secret: 421b54db25fec75eefa1525ed810d71c07168dd0d618956b6979691dbfe1c14af20af8216629ffd62b268e76709123050a191435cb582d183050ee55b2ff8e81
  bob   secret: 421b54db25fec75eefa1525ed810d71c07168dd0d618956b6979691dbfe1c14af20af8216629ffd62b268e76709123050a191435cb582d183050ee55b2ff8e81
  compare secrets: true
```

## Installation

Use the node package manager [npm](https://www.npmjs.com/) to install Node.js crypto cook book.

```bash
$ git clone https://github.com/rising3/crypto-cookbook-ts.git
$ cd crypto-cookbook-ts
$ npm i
```

## Usage

### start

Use the npm to run Node.js crypto cook book.

```bash
$ npm start
```

### test

Use the npm to test Node.js crypto cook book.

```bash
$ npm test

```

### build

Use the npm to build Node.js crypto cook book.

```bash
$ npm run build
```

## License

This project is licensed under the MIT License - see the LICENSE file for details
