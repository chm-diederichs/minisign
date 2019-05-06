// cases: line breaks etc?, emoji comment
var test = require('tape')
var minisign = require('../minisign')
var fs = require('fs')
var sodium = require('sodium-native')
var reverse = require('buffer-reverse')

test('MINISIGN generated key', function (t) {
  const comment = 'minisign public key A4570084F07E7F64'

  fs.readFile('./test/fixtures/minisign.pub', function (err, pubkey) {
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
  var keyGen = minisign.keypairGen('')
  var key = minisign.formatKeys(keyGen)

  var PKinfo = minisign.parsePubKey(key.PKoutputBuffer)
  var formatKeyID = PKinfo.keyID.toString('hex').toUpperCase()

  t.equals(PKinfo.untrustedComment.toString(), keyGen.PKcomment)
  t.equals(formatKeyID, keyGen.PKcomment.slice(20, 36))
  t.equals(PKinfo.publicKey.byteLength, sodium.crypto_sign_PUBLICKEYBYTES)
  t.end()
})

test('minisign generated key with comment removed', function (t) {
  fs.readFile('./test/fixtures/missingComment.pub', function (err, pubkey) {
    t.error(err)
    t.throws(() => minisign.parsePubKey(pubkey), '[ERR_ASSERTION]')
    t.end()
  })
})

test('key with long comment', function (t) {
  fs.readFile('./test/fixtures/longComment.pub', function (err, pubkey) {
    t.error(err)
    var PKinfo = minisign.parsePubKey(pubkey)

    t.equals(PKinfo.publicKey.byteLength, sodium.crypto_sign_PUBLICKEYBYTES)
    t.end()
  })
})

test('minisign key with one character removed', function (t) {
  fs.readFile('./test/fixtures/invalidKey.pub', function (err, pubkey) {
    t.error(err)
    t.throws(() => minisign.parsePubKey(pubkey), '[ERR_ASSERTION]')
    t.end()
  })
})

// test('minisign key with no line break')

// test('minisign key with extra line breaks')
