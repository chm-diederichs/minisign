var test = require('tape')
var minisign = require('../minisign')
var fs = require('fs')

test('key generation with empty password', function (t) {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength
  var noString = ''
  var comment = 'minisign encrypted secret key'

  var noPwdKey = minisign.keypairGen(comment, noString)

  var keyOutput = Buffer.concat([noPwdKey.fullComment, noPwdKey.SKinfo])

  t.deepEqual(keyOutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./fixtures/noString.key', function (err, SKinfo) {
    t.error(err)
    t.equal(keyOutput.byteLength, SKinfo.byteLength)
    t.end()
  })
})

test('key generation with string password', function (t) {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength
  var string = 'testing'
  var comment = 'minisign encrypted secret key'

  var stringPwdKey = minisign.keypairGen(comment, string)

  var keyOutput = Buffer.concat([stringPwdKey.fullComment, stringPwdKey.SKinfo])

  t.deepEqual(keyOutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./fixtures/string.key', function (err, SKinfo) {
    t.error(err)
    t.equal(keyOutput.byteLength, SKinfo.byteLength)
    t.end()
  })
})

test('key generation with emoji password', function (t) {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength
  var emojiString = 'testing👫'

  var emojiPwdKey = minisign.keypairGen(emojiString)

  var SKoutput = emojiPwdKey.SKoutputBuffer
  var PKoutput = emojiPwdKey.PKoutputBuffer
  var PKinfo = Buffer.from(PKoutput.slice(-57, -1).toString(), 'base64')

  t.deepEqual(PKoutput.subarray(0, endIndex), untrustedPrelude)
  t.deepEqual(SKoutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./fixtures/emojiString.key', function (err, SKinfo) {
    t.error(err)
    t.equal(SKoutput.byteLength, SKinfo.byteLength)
    t.deepEqual(emojiPwdKey.publicKey, PKinfo.subarray(-32))
    t.end()
  })
})

// have to add test for no comment provided. have to rewrite tests. --> now test PKoutput and SKoutput.
// now need to test all options combinations.
