var test = require('tape')
var minisign = require('../minisign')
var fs = require('fs')

test('key generation with empty password', function (t) {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength

  var noStringPwdKeyInfo = minisign.keypairGen('')
  var noStringPwdKey = minisign.formatKeys(noStringPwdKeyInfo)

  var SKoutput = noStringPwdKey.SKoutputBuffer
  var PKoutput = noStringPwdKey.PKoutputBuffer
  var PKinfo = Buffer.from(PKoutput.slice(-57, -1).toString(), 'base64')

  t.deepEqual(PKoutput.subarray(0, endIndex), untrustedPrelude)
  t.deepEqual(SKoutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./test/fixtures/noString.key', function (err, SKinfo) {
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

  var SKoutput = stringPwdKey.SKoutputBuffer
  var PKoutput = stringPwdKey.PKoutputBuffer
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

  var SKoutput = emojiPwdKey.SKoutputBuffer
  var PKoutput = emojiPwdKey.PKoutputBuffer
  var PKinfo = Buffer.from(PKoutput.slice(-57, -1).toString(), 'base64')

  t.deepEqual(PKoutput.subarray(0, endIndex), untrustedPrelude)
  t.deepEqual(SKoutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./test/fixtures/emojiString.key', function (err, SKinfo) {
    t.error(err)
    t.equal(SKoutput.byteLength, SKinfo.byteLength)
    t.deepEqual(emojiPwdKeyInfo.publicKey, PKinfo.subarray(-32))
    t.end()
  })
})
