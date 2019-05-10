var test = require('tape')
var minisign = require('../minisign.js')
var sodium = require('sodium-native')
var fs = require('fs')

test('sign empty content with minisign key, no tComment given', (t) => {
  var comment = 'untrusted comment: signature from minisign secret key'
  var noContent = Buffer.alloc(0)

  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  fs.readFile('./test/fixtures/minisign.key', (err, SK) => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(pwd, SKinfo)

    var signOutput = minisign.signContent(noContent, SKdetails)
    var parsedOutput = minisign.parseSignature(signOutput.outputBuf)
    var untrustedComment = signOutput.untrustedComment.toString()

    t.equal(untrustedComment.slice(0, untrustedComment.length - 1), comment)
    t.equal(signOutput.sigInfoBase64.length, 100)
    t.equal(signOutput.globalSigBase64.length, 89)

    fs.readFile('./test/fixtures/minisign.pub', (err, PK) => {
      t.error(err)
      var PKinfo = minisign.parsePubKey(PK)
      t.ok(minisign.verifySignature(parsedOutput, noContent, PKinfo))
      t.end()
    })
  })
})

test('sign emoji content with minisign key', (t) => {
  var comment = 'untrusted comment: signature from minisign secret key'

  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  fs.readFile('./test/fixtures/minisign.key', (err, SK) => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(pwd, SKinfo)

    fs.readFile('./test/fixtures/emoji.txt', (err, content) => {
      t.error(err)

      var signOutput = minisign.signContent(content, SKdetails)
      var parsedOutput = minisign.parseSignature(signOutput.outputBuf)
      var untrustedComment = signOutput.untrustedComment.toString()

      t.equal(untrustedComment.slice(0, untrustedComment.length - 1), comment)
      t.equal(signOutput.sigInfoBase64.length, 100)
      t.equal(signOutput.globalSigBase64.length, 89)

      fs.readFile('./test/fixtures/minisign.pub', (err, PK) => {
        t.error(err)
        var PKinfo = minisign.parsePubKey(PK)
        t.ok(minisign.verifySignature(parsedOutput, content, PKinfo))
        t.end()
      })
    })
  })
})

test('sign large input content, no opts', (t) => {
  var comment = 'untrusted comment: signature from minisign secret key'

  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  fs.readFile('./test/fixtures/minisign.key', (err, SK) => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(pwd, SKinfo)

    fs.readFile('./test/fixtures/long-comment.txt.minisig', (err, content) => {
      t.error(err)

      var signOutput = minisign.signContent(content, SKdetails)
      var parsedOutput = minisign.parseSignature(signOutput.outputBuf)

      var untrustedComment = signOutput.untrustedComment.toString()

      t.equal(untrustedComment.slice(0, untrustedComment.length - 1), comment)
      t.equal(signOutput.sigInfoBase64.length, 100)
      t.equal(signOutput.globalSigBase64.length, 89)

      fs.readFile('./test/fixtures/minisign.pub', (err, PK) => {
        t.error(err)
        var PKinfo = minisign.parsePubKey(PK)
        t.ok(minisign.verifySignature(parsedOutput, content, PKinfo))
        t.end()
      })
    })
  })
})

test('sign with large, emoji comment / tComment', (t) => {
  var comment = 'untrusted comment: signature from minisign secret key'
  var contentToSign = Buffer.from('sign me please.')

  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  fs.readFile('./test/fixtures/minisign.key', (err, SK) => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails1 = minisign.extractSecretKey(pwd, SKinfo)
    var SKdetails2 = minisign.extractSecretKey(pwd, SKinfo)

    fs.readFile('./test/fixtures/emoji.txt', (err, emoji) => {
      t.error(err)

      var opts1 = {
        comment: emoji.toString()
      }

      var opts2 = {
        tComment: emoji.toString()
      }

      var signOutput1 = minisign.signContent(contentToSign, SKdetails1, opts1)
      var untrustedComment1 = signOutput1.untrustedComment.toString().slice(19)
      var parsedOutput1 = minisign.parseSignature(signOutput1.outputBuf)

      var signOutput2 = minisign.signContent(contentToSign, SKdetails2, opts2)
      var untrustedComment2 = signOutput2.untrustedComment.toString()
      var parsedOutput2 = minisign.parseSignature(signOutput2.outputBuf)

      t.deepEqual(untrustedComment1.slice(0, -1), emoji.toString())
      t.equal(signOutput1.sigInfoBase64.length, 100)
      t.equal(signOutput1.globalSigBase64.length, 89)

      t.equal(untrustedComment2.slice(0, untrustedComment2.length - 1), comment)
      t.equal(signOutput2.sigInfoBase64.length, 100)
      t.equal(signOutput2.globalSigBase64.length, 89)

      fs.readFile('./test/fixtures/minisign.pub', (err, PK) => {
        t.error(err)
        var PKinfo = minisign.parsePubKey(PK)
        t.ok(minisign.verifySignature(parsedOutput1, contentToSign, PKinfo))
        t.ok(sodium.crypto_sign_verify_detached(parsedOutput2.signature, contentToSign, PKinfo.publicKey))
        t.ok(minisign.verifySignature(parsedOutput2, contentToSign, PKinfo))
        t.end()
      })
    })
  })
})

test('use invalid secret key', (t) => {
  var toSign = Buffer.from('sign me please.')

  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  fs.readFile('./test/fixtures/no-comment.key', (err, SK) => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(pwd, SKinfo)

    fs.readFile('./test/fixtures/example.txt', (err, content) => {
      t.error(err)

      var signOutput = minisign.signContent(toSign, SKdetails)
      var parsedOutput = minisign.parseSignature(signOutput.outputBuf)

      fs.readFile('./test/fixtures/minisign.pub', (err, PK) => {
        t.error(err)

        var PKinfo = minisign.parsePubKey(PK)
        t.throws(() => minisign.verifySignature(parsedOutput, toSign, PKinfo), 'signature verification failed')
        t.end()
      })
    })
  })
})

test('prehash and sign', (t) => {
  var comment = 'untrusted comment: signature from minisign secret key'
  var contentToSign = Buffer.from('sign me please.')

  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  fs.readFile('./test/fixtures/minisign.key', (err, SK) => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(pwd, SKinfo)

    fs.readFile('./test/fixtures/long-trusted-comment.txt', (err, content) => {
      t.error(err)

      var opts = {
        tComment: content.toString(),
        sigAlgorithm: 'ED'
      }

      var signOutput = minisign.signContent(contentToSign, SKdetails, opts)
      var parsedOutput = minisign.parseSignature(signOutput.outputBuf)
      var untrustedComment = signOutput.untrustedComment.toString()

      t.equal(untrustedComment.slice(0, untrustedComment.length - 1), comment)
      t.equal(signOutput.sigInfoBase64.length, 100)
      t.equal(signOutput.globalSigBase64.length, 89)

      fs.readFile('./test/fixtures/minisign.pub', (err, PK) => {
        t.error(err)
        var PKinfo = minisign.parsePubKey(PK)
        t.ok(minisign.verifySignature(parsedOutput, contentToSign, PKinfo))
        t.end()
      })
    })
  })
})

test('use invalid signature algorithm', (t) => {
  var toSign = Buffer.from('sign me please.')

  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  fs.readFile('./test/fixtures/no-comment.key', (err, SK) => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(pwd, SKinfo)

    fs.readFile('./test/fixtures/example.txt', (err, content) => {
      t.error(err)

      var opts = {
        sigAlgorithm: 'eD'
      }

      t.throws(() => minisign.signContent(toSign, SKdetails, opts), 'algorithm not recognised')
      t.end()
    })
  })
})

test('sign with keypairGen keys', (t) => {
  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  var keyGen = minisign.keypairGen(pwd)
  var key = minisign.formatKeys(keyGen)

  var PK = minisign.parsePubKey(key.PK)
  var SKinfo = minisign.parseSecretKey(key.SK)
  var SK = minisign.extractSecretKey(pwd, SKinfo)

  var toSign = Buffer.from('sign me please.')

  var signOutput = minisign.signContent(toSign, SK)
  var parsedOutput = minisign.parseSignature(signOutput.outputBuf)

  t.ok(minisign.verifySignature(parsedOutput, toSign, PK))
  t.end()
})
