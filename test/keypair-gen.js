var test = require('tape')
var minisign = require('../minisign')
var fs = require('fs')

test('key generation with empty password', function (t) {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength

  var noStringPwdKeyInfo = minisign.keypairGen('')
  var noStringPwdKey = minisign.formatKeys(noStringPwdKeyInfo)

  var SKoutput = noStringPwdKey.SK
  var PKoutput = noStringPwdKey.PK
  var PKinfo = Buffer.from(PKoutput.slice(-57, -1).toString(), 'base64')

  t.deepEqual(PKoutput.subarray(0, endIndex), untrustedPrelude)
  t.deepEqual(SKoutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./test/fixtures/no-string.key', function (err, SKinfo) {
    t.error(err)
    t.equal(SKoutput.byteLength, SKinfo.byteLength)
    t.deepEqual(noStringPwdKeyInfo.publicKey, PKinfo.subarray(-32))
    t.end()
  })
})

test('key generation with string password', function (t) {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength

  var stringPwdKeyInfo = minisign.keypairGen('testing')
  var stringPwdKey = minisign.formatKeys(stringPwdKeyInfo)

  var SKoutput = stringPwdKey.SK
  var PKoutput = stringPwdKey.PK
  var PKinfo = Buffer.from(PKoutput.slice(-57, -1).toString(), 'base64')

  t.deepEqual(PKoutput.subarray(0, endIndex), untrustedPrelude)
  t.deepEqual(SKoutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./test/fixtures/string.key', function (err, SKinfo) {
    t.error(err)
    t.equal(SKoutput.byteLength, SKinfo.byteLength)
    t.deepEqual(stringPwdKeyInfo.publicKey, PKinfo.subarray(-32))
    t.end()
  })
})

test('key generation with emoji password', function (t) {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength

  var emojiPwdKeyInfo = minisign.keypairGen('testing👫')
  var emojiPwdKey = minisign.formatKeys(emojiPwdKeyInfo)

  var SKoutput = emojiPwdKey.SK
  var PKoutput = emojiPwdKey.PK
  var PKinfo = Buffer.from(PKoutput.slice(-57, -1).toString(), 'base64')

  t.deepEqual(PKoutput.subarray(0, endIndex), untrustedPrelude)
  t.deepEqual(SKoutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./test/fixtures/emoji-string.key', function (err, SKinfo) {
    t.error(err)
    t.equal(SKoutput.byteLength, SKinfo.byteLength)
    t.deepEqual(emojiPwdKeyInfo.publicKey, PKinfo.subarray(-32))
    t.end()
  })
})

test('keypairGen with only one comment', function (t) {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var startIndex = untrustedPrelude.byteLength
  var comment1 = Buffer.from('this will appear in both keys')
  var comment2 = Buffer.from('as should this.')
  var endIndex1 = comment1.byteLength + startIndex
  var endIndex2 = comment2.byteLength + startIndex

  var opts1 = {
    PKcomment: comment1.toString()
  }
  var opts2 = {
    SKcomment: comment2.toString()
  }

  var keyGenOpts1 = minisign.keypairGen('', opts1)
  var keyOpts1 = minisign.formatKeys(keyGenOpts1)
  var PKopts1 = keyOpts1.PK
  var SKopts1 = keyOpts1.SK

  var keyGenOpts2 = minisign.keypairGen('', opts2)
  var keyOpts2 = minisign.formatKeys(keyGenOpts2)
  var PKopts2 = keyOpts2.PK
  var SKopts2 = keyOpts2.SK

  t.equal(keyOpts1.PKcomment, keyOpts1.SKcomment)
  t.equal(keyOpts2.PKcomment, keyOpts2.SKcomment)
  t.deepEqual(PKopts1.subarray(startIndex, endIndex1), comment1)
  t.deepEqual(SKopts1.subarray(startIndex, endIndex1), comment1)
  t.deepEqual(PKopts2.subarray(startIndex, endIndex2), comment2)
  t.deepEqual(SKopts2.subarray(startIndex, endIndex2), comment2)
  t.end()
})
