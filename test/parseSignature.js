var test = require('tape')
var minisign = require('../minisign')
var sodium = require('sodium-native')
var fs = require('fs')

test('MINISIGN signature from file', function (t) {
  fs.readFile('./fixtures/example.txt.minisig', function (err, signature) {
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
  fs.readFile('./fixtures/noComment.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
    t.end()
  })
})

test('long comment (180KB)', function (t) {
  fs.readFile('./fixtures/longComment.txt.minisig', function (err, signature) {
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
  fs.readFile('./fixtures/noTrustedComment.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
    t.end()
  })
})

test('long trusted comment (164KB)', function (t) {
  fs.readFile('./fixtures/longTrustedComment.txt.minisig', function (err, signature) {
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
  fs.readFile('./fixtures/preHashed.txt.minisig', function (err, signature) {
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
  fs.readFile('./fixtures/noLineBreaks.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
  })
  fs.readFile('./fixtures/missingLineBreak.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
    t.end()
  })
})

test('extra line break', function (t) {
  fs.readFile('./fixtures/extraLineBreak1.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
  })
  fs.readFile('./fixtures/extraLineBreak2.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
  })
  fs.readFile('./fixtures/extraLineBreak3.txt.minisig', function (err, signature) {
    t.error(err)
    t.throws(() => minisign.parseSignature(signature), '[ERR_ASSERTION]')
    t.end()
  })
})

test('MINISIGN signature using minisign.js key', function (t) {
  fs.readFile('./fixtures/keypairGen.txt.minisig', function (err, signature) {
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

  fs.readFile('./fixtures/minisign.key', function (err, SK) {
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
