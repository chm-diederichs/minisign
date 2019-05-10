// cases: line breaks etc?, emoji comment
var test = require('tape')
var minisign = require('../minisign')
var fs = require('fs')
var sodium = require('sodium-native')
var reverse = require('buffer-reverse')

test('minisign generated key', (t) => {
  const comment = 'minisign public key A4570084F07E7F64'

  fs.readFile('./test/fixtures/minisign.pub', (err, pubkey) => {
    var PKinfo = minisign.parsePubKey(pubkey)
    var formatKeyID = reverse(PKinfo.keyID).toString('hex').toUpperCase()

    t.error(err)
    t.equals(PKinfo.untrustedComment.toString(), comment)
    t.equals(formatKeyID, comment.slice(20, 36))
    t.equals(PKinfo.publicKey.byteLength, sodium.crypto_sign_PUBLICKEYBYTES)
    t.end()
  })
})

test('minisign.js generated key', (t) => {
  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  var keyGen = minisign.keypairGen(pwd)
  var key = minisign.formatKeys(keyGen)

  var PKinfo = minisign.parsePubKey(key.PK)
  var formatKeyID = PKinfo.keyID.toString('hex').toUpperCase()

  t.equals(PKinfo.untrustedComment.toString(), keyGen.PKcomment)
  t.equals(formatKeyID, keyGen.PKcomment.slice(20, 36))
  t.equals(PKinfo.publicKey.byteLength, sodium.crypto_sign_PUBLICKEYBYTES)
  t.end()
})

test('minisign generated key with comment removed', (t) => {
  fs.readFile('./test/fixtures/missing-comment.pub', (err, pubkey) => {
    t.error(err)
    t.throws(() => minisign.parsePubKey(pubkey), 'file format not recognised')
    t.end()
  })
})

test('key with long comment', (t) => {
  fs.readFile('./test/fixtures/long-comment.pub', (err, pubkey) => {
    t.error(err)
    var PKinfo = minisign.parsePubKey(pubkey)

    t.equals(PKinfo.publicKey.byteLength, sodium.crypto_sign_PUBLICKEYBYTES)
    t.end()
  })
})

test('minisign key with one character removed', (t) => {
  fs.readFile('./test/fixtures/invalid-key.pub', (err, pubkey) => {
    t.error(err)
    t.throws(() => minisign.parsePubKey(pubkey), 'file format not recognised')
    t.end()
  })
})

test('minisign key with no line break', (t) => {
  fs.readFile('./test/fixtures/no-line-break.pub', (err, pubkey) => {
    t.error(err)
    t.throws(() => minisign.parsePubKey(pubkey), 'file format not recognised')
    t.end()
  })
})

test('minisign key with extra line breaks', (t) => {
  fs.readFile('./test/fixtures/extra-line-breaks1.pub', (err, pubkey) => {
    t.error(err)
    t.throws(() => minisign.parsePubKey(pubkey), 'file format not recognised')
  })
  fs.readFile('./test/fixtures/extra-line-breaks2.pub', (err, pubkey) => {
    t.error(err)
    t.throws(() => minisign.parsePubKey(pubkey), 'file format not recognised')
    t.end()
  })
})
