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

// cases to test: signContent output

// for reference
function parseSignature (signatureBuf) {
  assert(untrustedPrelude.equals(signatureBuf.subarray(0, untrustedCommentStart)))

  const untrustedCommentEnd = signatureBuf.indexOf('\n', untrustedCommentStart)
  const untrustedComment = signatureBuf.subarray(untrustedCommentStart, untrustedCommentEnd)

  const sigInfoStart = untrustedCommentEnd + 1
  const sigInfoEnd = signatureBuf.indexOf('\n', sigInfoStart)
  const sigInfoBase64 = signatureBuf.subarray(sigInfoStart, sigInfoEnd).toString()
  const sigInfo = Buffer.from(sigInfoBase64, 'base64')

  const signatureAlgorithm = sigInfo.subarray(0, 2)
  const keyID = sigInfo.subarray(2, 10)
  const signature = sigInfo.subarray(10, sigInfoEnd)

  const trustedCommentStart = sigInfoEnd + 1 + trustedPrelude.byteLength
  const trustedCommentEnd = signatureBuf.indexOf('\n', trustedCommentStart)
  const trustedComment = signatureBuf.subarray(trustedCommentStart, trustedCommentEnd)

  const globalSignatureBase64 = signatureBuf.subarray(trustedCommentEnd + 1).toString()
  const globalSignature = Buffer.from(globalSignatureBase64, 'base64')

  return {
    untrustedComment,
    signatureAlgorithm,
    keyID,
    signature,
    trustedComment,
    globalSignature
  }
}