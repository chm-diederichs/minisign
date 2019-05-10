var test = require('tape')
var minisign = require('../minisign')
var fs = require('fs')
var sodium = require('sodium-native')

test('key generation with empty password', (t) => {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength

  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  var noStringPwdKeyInfo = minisign.keypairGen(pwd)
  var noStringPwdKey = minisign.formatKeys(noStringPwdKeyInfo)

  var SKoutput = noStringPwdKey.SK
  var PKoutput = noStringPwdKey.PK
  var PKinfo = Buffer.from(PKoutput.slice(-57, -1).toString(), 'base64')

  t.deepEqual(PKoutput.subarray(0, endIndex), untrustedPrelude)
  t.deepEqual(SKoutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./test/fixtures/no-string.key', (err, SKinfo) => {
    t.error(err)
    t.equal(SKoutput.byteLength, SKinfo.byteLength)
    t.deepEqual(noStringPwdKeyInfo.publicKey, PKinfo.subarray(-32))
    t.end()
  })
})

test('key generation with string password', (t) => {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength

  var stringBuf = Buffer.from('testing')
  var pwd = sodium.sodium_malloc(stringBuf.byteLength)
  pwd.fill(stringBuf)

  var stringPwdKeyInfo = minisign.keypairGen(pwd)
  var stringPwdKey = minisign.formatKeys(stringPwdKeyInfo)

  var SKoutput = stringPwdKey.SK
  var PKoutput = stringPwdKey.PK
  var PKinfo = Buffer.from(PKoutput.slice(-57, -1).toString(), 'base64')

  t.deepEqual(PKoutput.subarray(0, endIndex), untrustedPrelude)
  t.deepEqual(SKoutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./test/fixtures/string.key', (err, SKinfo) => {
    t.error(err)
    t.equal(SKoutput.byteLength, SKinfo.byteLength)
    t.deepEqual(stringPwdKeyInfo.publicKey, PKinfo.subarray(-32))
    t.end()
  })
})

test('key generation with emoji password', (t) => {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength

  var emojiBuf = Buffer.from('testing👫')
  var pwd = sodium.sodium_malloc(emojiBuf.byteLength)
  pwd.fill(emojiBuf)

  var emojiPwdKeyInfo = minisign.keypairGen(pwd)
  var emojiPwdKey = minisign.formatKeys(emojiPwdKeyInfo)

  var SKoutput = emojiPwdKey.SK
  var PKoutput = emojiPwdKey.PK
  var PKinfo = Buffer.from(PKoutput.slice(-57, -1).toString(), 'base64')

  t.deepEqual(PKoutput.subarray(0, endIndex), untrustedPrelude)
  t.deepEqual(SKoutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./test/fixtures/emoji-string.key', (err, SKinfo) => {
    t.error(err)
    t.equal(SKoutput.byteLength, SKinfo.byteLength)
    t.deepEqual(emojiPwdKeyInfo.publicKey, PKinfo.subarray(-32))
    t.end()
  })
})

test('keypairGen with only one comment', (t) => {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var startIndex = untrustedPrelude.byteLength
  var comment1 = Buffer.from('this will appear in public key,')
  var comment2 = Buffer.from('but this appears in secret key.')
  var endIndex1 = comment1.byteLength + startIndex
  var endIndex2 = comment2.byteLength + startIndex

  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  var opts1 = {
    PKcomment: comment1.toString()
  }
  var opts2 = {
    SKcomment: comment2.toString()
  }

  var keyGenOpts1 = minisign.keypairGen(pwd, opts1)
  var keyOpts1 = minisign.formatKeys(keyGenOpts1)

  var keyGenOpts2 = minisign.keypairGen(pwd, opts2)
  var keyOpts2 = minisign.formatKeys(keyGenOpts2)

  t.equal(keyOpts1.PKcomment, keyOpts1.SKcomment)
  t.equal(keyOpts2.PKcomment, keyOpts2.SKcomment)
  t.deepEqual(keyOpts1.PK.subarray(startIndex, endIndex1), comment1)
  t.deepEqual(keyOpts2.SK.subarray(startIndex, endIndex2), comment2)
  t.end()
})
