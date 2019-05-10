// cases: signContent input
var test = require('tape')
var minisign = require('../minisign.js')
var fs = require('fs')
var sodium = require('sodium-native')

test('verify minisign generated signature', (t) => {
  fs.readFile('./test/fixtures/example.txt.minisig', (err, signature) => {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', (err, content) => {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', (err, publicKeyBuf) => {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        var parsedSignature = minisign.parseSignature(signature)

        t.ok(minisign.verifySignature(parsedSignature, content, PKinfo))
        t.end()
      })
    })
  })
})

test('PK ID != SK ID', (t) => {
  fs.readFile('./test/fixtures/example.txt.minisig', (err, signature) => {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', (err, content) => {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', (err, publicKeyBuf) => {
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

test('verify minisign prehashed signature', (t) => {
  fs.readFile('./test/fixtures/pre-hashed.txt.minisig', (err, signature) => {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', (err, content) => {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', (err, publicKeyBuf) => {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        var parsedSignature = minisign.parseSignature(signature)

        t.ok(minisign.verifySignature(parsedSignature, content, PKinfo))
        t.end()
      })
    })
  })
})

test('same key, different content', (t) => {
  fs.readFile('./test/fixtures/wrong-info.txt.minisig', (err, signature) => {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', (err, content) => {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', (err, publicKeyBuf) => {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        var parsedSignature = minisign.parseSignature(signature)

        t.throws(() => minisign.verifySignature(parsedSignature, content, PKinfo), 'signature verification failed')
        t.end()
      })
    })
  })
})

test('globalSignature altered', (t) => {
  fs.readFile('./test/fixtures/wrong-global-sig.txt.minisig', (err, signature) => {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', (err, content) => {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', (err, publicKeyBuf) => {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        var parsedSignature = minisign.parseSignature(signature)

        t.throws(() => minisign.verifySignature(parsedSignature, content, PKinfo), 'trusted comment cannot be verified')
        t.end()
      })
    })
  })
})

test('emoji trusted comment', (t) => {
  fs.readFile('./test/fixtures/emoji-comment.txt.minisig', (err, signature) => {
    t.error(err)
    fs.readFile('./test/fixtures/example.txt', (err, content) => {
      t.error(err)
      fs.readFile('./test/fixtures/minisign.pub', (err, publicKeyBuf) => {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        var parsedSignature = minisign.parseSignature(signature)

        t.ok(minisign.verifySignature(parsedSignature, content, PKinfo))
        t.end()
      })
    })
  })
})

test('signContent generated input', (t) => {
  var toSign = Buffer.alloc(200)
  sodium.randombytes_buf(toSign)

  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)

  fs.readFile('./test/fixtures/minisign.key', (err, SK) => {
    t.error(err)

    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(pwd, SKinfo)

    var signedOutput = minisign.signContent(toSign, SKdetails).outputBuf
    var parsedOutput = minisign.parseSignature(signedOutput)

    fs.readFile('./test/fixtures/minisign.pub', (err, PK) => {
      t.error(err)
      var PKinfo = minisign.parsePubKey(PK)
      t.ok(minisign.verifySignature(parsedOutput, toSign, PKinfo))
      t.end()
    })
  })
})
