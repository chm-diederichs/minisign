// cases: signContent input
var test = require('tape')
var minisign = require('../minisign.js')
var fs = require('fs')
var sodium = require('sodium-native')

test('verify minisign generated signature', function (t) {
  fs.readFile('./test/fixtures/example.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        var parsedSignature = minisign.parseSignature(signature)

        t.ok(minisign.verifySignature(parsedSignature, content, PKinfo))
        t.end()
      })
    })
  })
})

test('PK ID != SK ID', function (t) {
  fs.readFile('./test/fixtures/example.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        var parsedSignature = minisign.parseSignature(signature)

        PKinfo.keyID.fill(1)
        t.throws(() => minisign.verifySignature(parsedSignature, content, PKinfo), "keyID's do not match")
        t.end()
      })
    })
  })
})

test('verify minisign prehashed signature', function (t) {
  fs.readFile('./test/fixtures/pre-hashed.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        var parsedSignature = minisign.parseSignature(signature)

        t.ok(minisign.verifySignature(parsedSignature, content, PKinfo))
        t.end()
      })
    })
  })
})

test('same key, different content', function (t) {
  fs.readFile('./test/fixtures/wrong-info.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        var parsedSignature = minisign.parseSignature(signature)

        t.throws(() => minisign.verifySignature(parsedSignature, content, PKinfo), 'signature verification failed')
        t.end()
      })
    })
  })
})

test('globalSignature altered', function (t) {
  fs.readFile('./test/fixtures/wrong-global-sig.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        var parsedSignature = minisign.parseSignature(signature)

        t.throws(() => minisign.verifySignature(parsedSignature, content, PKinfo), 'trusted comment cannot be verified')
        t.end()
      })
    })
  })
})

test('emoji trusted comment', function (t) {
  fs.readFile('./test/fixtures/emoji-comment.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        var parsedSignature = minisign.parseSignature(signature)

        t.ok(minisign.verifySignature(parsedSignature, content, PKinfo))
        t.end()
      })
    })
  })
})

test('signContent generated input', function (t) {
  var toSign = Buffer.alloc(200)
  sodium.randombytes_buf(toSign)

  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  fs.readFile('./test/fixtures/minisign.key', function (err, SK) {
    t.error(err)

    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(pwd, SKinfo)

    var signedOutput = minisign.signContent(toSign, SKdetails).outputBuf
    var parsedOutput = minisign.parseSignature(signedOutput)

    fs.readFile('./test/fixtures/minisign.pub', function (err, PK) {
      t.error(err)
      var PKinfo = minisign.parsePubKey(PK)
      t.ok(minisign.verifySignature(parsedOutput, toSign, PKinfo))
      t.end()
    })
  })
})
