var test = require('tape')
var minisign = require('../minisign')
var sodium = require('sodium-native')
var fs = require('fs')

test('MINISIGN signature from file', function (t) {
  fs.readFile('./test/fixtures/example.txt.minisig', function (err, signature) {
    t.error(err)
    var sigInfo = minisign.parseSignature(signature)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('Ed'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})

test('comment line removed', function (t) {
  fs.readFile('./test/fixtures/no-comment.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
    t.end()
  })
})

test('long comment (180KB)', function (t) {
  fs.readFile('./test/fixtures/long-comment.txt.minisig', function (err, signature) {
    t.error(err)
    var sigInfo = minisign.parseSignature(signature)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('Ed'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})

test('trusted comment line removed', function (t) {
  fs.readFile('./test/fixtures/no-trusted-comment.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
    t.end()
  })
})

test('long trusted comment (164KB)', function (t) {
  fs.readFile('./test/fixtures/long-trusted-comment.txt.minisig', function (err, signature) {
    t.error(err)
    var sigInfo = minisign.parseSignature(signature)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('Ed'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})

test('pre hashed content', function (t) {
  fs.readFile('./test/fixtures/pre-hashed.txt.minisig', function (err, signature) {
    t.error(err)
    var sigInfo = minisign.parseSignature(signature)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('ED'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})

test('no line breaks', function (t) {
  fs.readFile('./test/fixtures/no-line-breaks.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
  })
  fs.readFile('./test/fixtures/missing-line-break.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
    t.end()
  })
})

test('extra line break', function (t) {
  fs.readFile('./test/fixtures/extra-line-break1.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
  })
  fs.readFile('./test/fixtures/extra-line-break2.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
  })
  fs.readFile('./test/fixtures/extra-line-break3.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
    t.end()
  })
})

test('MINISIGN signature using minisign.js key', function (t) {
  fs.readFile('./test/fixtures/keypair-gen.txt.minisig', function (err, signature) {
    t.error(err)
    var sigInfo = minisign.parseSignature(signature)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('Ed'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})

test('signContent generated input', function (t) {
  var toSign = Buffer.alloc(200)
  sodium.randombytes_buf(toSign)

  fs.readFile('./test/fixtures/minisign.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey('', SKinfo)

    var signedOutput = minisign.signContent(toSign, SKdetails).outputBuf
    var sigInfo = minisign.parseSignature(signedOutput)

    t.equal(sigInfo.signature.length, sodium.crypto_sign_BYTES)
    t.deepEqual(sigInfo.signatureAlgorithm, Buffer.from('Ed'))
    t.equal(sigInfo.keyID.byteLength, 8)
    t.equal(sigInfo.globalSignature.length, sodium.crypto_sign_BYTES)
    t.end()
  })
})
