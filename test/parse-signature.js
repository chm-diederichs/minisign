var test = require('tape')
var minisign = require('../minisign')
var sodium = require('sodium-native')
var fs = require('fs')

test('minisign signature from file', (t) => {
  fs.readFile('./test/fixtures/example.txt.minisig', (err, signature) => {
    t.error(err)
    var sigInfo = minisign.parseSignature(signature)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('Ed'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})

test('comment line removed', (t) => {
  fs.readFile('./test/fixtures/no-comment.txt.minisig', (err, signature) => {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), 'file format not recognised')
    t.end()
  })
})

test('long comment (180KB)', (t) => {
  fs.readFile('./test/fixtures/long-comment.txt.minisig', (err, signature) => {
    t.error(err)
    var sigInfo = minisign.parseSignature(signature)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('Ed'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})

test('trusted comment line removed', (t) => {
  fs.readFile('./test/fixtures/no-trusted-comment.txt.minisig', (err, signature) => {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), 'file format not recognised')
    t.end()
  })
})

test('long trusted comment (164KB)', (t) => {
  fs.readFile('./test/fixtures/long-trusted-comment.txt.minisig', (err, signature) => {
    t.error(err)
    var sigInfo = minisign.parseSignature(signature)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('Ed'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})

test('pre hashed content', (t) => {
  fs.readFile('./test/fixtures/pre-hashed.txt.minisig', (err, signature) => {
    t.error(err)
    var sigInfo = minisign.parseSignature(signature)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('ED'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})

test('no line breaks', (t) => {
  fs.readFile('./test/fixtures/no-line-breaks.txt.minisig', (err, signature) => {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), 'file format not recognised')
  })
  fs.readFile('./test/fixtures/missing-line-break.txt.minisig', (err, signature) => {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), 'file format not recognised')
    t.end()
  })
})

test('extra line break', (t) => {
  fs.readFile('./test/fixtures/extra-line-break1.txt.minisig', (err, signature) => {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), 'file format not recognised')
  })
  fs.readFile('./test/fixtures/extra-line-break2.txt.minisig', (err, signature) => {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), 'file format not recognised')
  })
  fs.readFile('./test/fixtures/extra-line-break3.txt.minisig', (err, signature) => {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), 'file format not recognised')
    t.end()
  })
})

test('minisign signature using minisign.js key', (t) => {
  fs.readFile('./test/fixtures/keypair-gen.txt.minisig', (err, signature) => {
    t.error(err)
    var sigInfo = minisign.parseSignature(signature)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('Ed'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})

test('signContent generated input', (t) => {
  var toSign = Buffer.alloc(200)
  sodium.randombytes_buf(toSign)

  fs.readFile('./test/fixtures/minisign.key', (err, SK) => {
    t.error(err)
    var emptyBuf = Buffer.from('')
    var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
    pwd.fill(emptyBuf)

    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(pwd, SKinfo)

    var signedOutput = minisign.signContent(toSign, SKdetails).outputBuf
    var sigInfo = minisign.parseSignature(signedOutput)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('ED'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})
