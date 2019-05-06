// cases: line breaks etc?, emoji comment
var test = require('tape')
var minisign = require('../minisign')
var fs = require('fs')
var sodium = require('sodium-native')
var reverse = require('buffer-reverse')

test('MINISIGN generated key', function (t) {
  const comment = 'minisign public key A4570084F07E7F64'

  fs.readFile('./fixtures/minisign.pub', function (err, pubkey) {
    var PKinfo = minisign.parsePubKey(pubkey)
    var formatKeyID = reverse(PKinfo.keyID).toString('hex').toUpperCase()

    t.error(err)
    t.equals(PKinfo.untrustedComment.toString(), comment)
    t.equals(formatKeyID, comment.slice(20, 36))
    t.equals(PKinfo.publicKey.byteLength, sodium.crypto_sign_PUBLICKEYBYTES)
    t.end()
  })
})

test('minisign.js generated key', function (t) {
  const comment = 'minisign public key 4C2AA548072B9EE7'

  fs.readFile('./fixtures/keypairGen.pub', function (err, pubkey) {
    var PKinfo = minisign.parsePubKey(pubkey)
    var formatKeyID = PKinfo.keyID.toString('hex').toUpperCase()

    t.error(err)
    t.equals(PKinfo.untrustedComment.toString(), comment)
    t.equals(formatKeyID, comment.slice(20, 36))
    t.equals(PKinfo.publicKey.byteLength, sodium.crypto_sign_PUBLICKEYBYTES)
    t.end()
  })
})

test('minisign generated key with comment removed', function (t) {
  fs.readFile('./fixtures/missingComment.pub', function (err, pubkey) {
    t.error(err)
    t.throws(() => minisign.parsePubKey(pubkey), '[ERR_ASSERTION]')
    t.end()
  })
})

test('key with long comment', function (t) {
  fs.readFile('./fixtures/longComment.pub', function (err, pubkey) {
    t.error(err)
    var PKinfo = minisign.parsePubKey(pubkey)

    t.equals(PKinfo.publicKey.byteLength, sodium.crypto_sign_PUBLICKEYBYTES)
    t.end()
  })
})

test('minisign key with one character removed', function (t) {
  fs.readFile('./fixtures/invalidKey.pub', function (err, pubkey) {
    t.error(err)
    t.throws(() => minisign.parsePubKey(pubkey), '[ERR_ASSERTION]')
    t.end()
  })
})

test('minisign key with no line break')

test('minisign key with extra line breaks')

// for reference
function parsePubKey (pubkeyBuf) {
  //assert(untrustedPrelude.equals(pubkeyBuf.subarray(0, untrustedCommentStart)))
  const untrustedCommentEnd = pubkeyBuf.indexOf('\n', untrustedCommentStart)
  const untrustedComment = pubkeyBuf.subarray(untrustedCommentStart, untrustedCommentEnd)

  const keyInfoStart = untrustedCommentStart + untrustedComment.byteLength + 1
  const keyInfoBase64 = pubkeyBuf.subarray(keyInfoStart, pubkeyBuf.indexOf('\n', keyInfoStart)).toString()
  const keyInfo = Buffer.from(keyInfoBase64, 'base64')

  const signatureAlgorithm = keyInfo.subarray(0, 2)
  const keyID = keyInfo.subarray(2, 10)
  const publicKey = keyInfo.subarray(10)

  //assert(signatureAlgorithm.equals(expectedSignatureAlgorithm))
  return {
    untrustedComment,
    signatureAlgorithm,
    keyID,
    publicKey
  }
}