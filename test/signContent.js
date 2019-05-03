// cases: no content, emoji content, extremely large file, no tcomment, massive tcomment, invalid secretKey, prehash`
var test = require('tape')
var minisign = require('../minisign.js')
var fs = require('fs')
var sodium = require('sodium-native')

test('sign empty content with MINISIGN key, no tComment given', function (t) {
  var comment = 'untrusted comment: signature from minisign secret key'
  var noContent = Buffer.alloc(0)

  fs.readFile('./fixtures/minisign.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey('', SKinfo)

    var signOutput = minisign.signContent(noContent, SKdetails)
    var untrustedComment = signOutput.untrustedComment.toString()

    t.equal(untrustedComment.slice(0, untrustedComment.length - 1), comment)
    t.equal(signOutput.sigInfoBase64.length, 100)
    t.equal(signOutput.globalSigBase64.length, 89)

    fs.readFile('./fixtures/minisign.pub', function (err, PK) {
      t.error(err)
      var PKinfo = minisign.parsePubKey(PK)
      t.ok(minisign.verifySignature(signOutput.outputBuf, noContent, PKinfo))
      t.end()
    })
  })
})

test('sign empty content with MINISIGN key, emoji tComment given', function (t) {
  var comment = 'untrusted comment: signature from minisign secret key'
  var noContent = Buffer.alloc(0)
  var emojiString = 'testing👫'

  fs.readFile('./fixtures/minisign.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey('', SKinfo)

    var signOutput = minisign.signContent(noContent, SKdetails, comment.slice(19), emojiString)
    var untrustedComment = signOutput.untrustedComment.toString()

    t.equal(untrustedComment.slice(0, untrustedComment.length - 1), comment)
    t.equal(signOutput.sigInfoBase64.length, 100)
    t.equal(signOutput.globalSigBase64.length, 89)

    fs.readFile('./fixtures/minisign.pub', function (err, PK) {
      t.error(err)
      var PKinfo = minisign.parsePubKey(PK)
      t.ok(minisign.verifySignature(signOutput.outputBuf, noContent, PKinfo))
      t.end()
    })
  })
})

// for reference
function signContent (content, comment, SKdetails, trustComment, sigAlgorithm = 'Ed') {
  var contentToSign
  var signatureAlgorithm

  if (sigAlgorithm === 'ED') {
    var hashedContent = Buffer.alloc(sodium.crypto_generichash_BYTES_MAX)
    sodium.crypto_generichash(hashedContent, content)
    contentToSign = hashedContent
    signatureAlgorithm = Buffer.from(sigAlgorithm)
  } else {
    contentToSign = content
    signatureAlgorithm = Buffer.from(SKdetails.signatureAlgorithm)
  }

  var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  var globalSignature = Buffer.alloc(sodium.crypto_sign_BYTES)

  sodium.crypto_sign_detached(signature, contentToSign, SKdetails.secretKey)

  var signatureInfo = Buffer.concat([signatureAlgorithm, SKdetails.keyID, signature])
  var untrustedComment = Buffer.from('untrusted comment: ' + comment + '\n')
  var trustedComment = Buffer.from('\ntrusted comment: ' + trustComment.toString('ascii') + '\n')
  var sigInfoBase64 = Buffer.from(signatureInfo.toString('base64'))
  var globalSigBase64 = Buffer.from(globalSignature.toString('base64'))

  var forGlobalSig = Buffer.concat([signature, Buffer.from(trustComment)])
  sodium.crypto_sign_detached(globalSignature, forGlobalSig, SKdetails.secretKey)

  return Buffer.concat([untrustedComment, sigInfoBase64, trustedComment, globalSigBase64])
}