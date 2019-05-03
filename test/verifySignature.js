// cases: signContent input
var test = require('tape')
var minisign = require('../minisign.js')
var fs = require('fs')
var sodium = require('sodium-native')
var xor = require('buffer-xor')

test('verify minisign generated signature', function (t) {
  fs.readFile('./fixtures/example.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        t.ok(minisign.verifySignature(signature, content, PKinfo))
        t.end()
      })
    })
  })
})

test('PK ID != SK ID', function (t) {
  fs.readFile('./fixtures/example.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)

        PKinfo.keyID.fill(1)
        t.throws(() => minisign.verifySignature(signature, content, PKinfo), "keyID's do not match")
        t.end()
      })
    })
  })
})

test('verify minisign prehashed signature', function (t) {
  fs.readFile('./fixtures/preHashed.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        t.ok(minisign.verifySignature(signature, content, PKinfo))
        t.end()
      })
    })
  })
})

test('same key, different content', function (t) {
  fs.readFile('./fixtures/wrongInfo.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)

        t.throws(() => minisign.verifySignature(signature, content, PKinfo), 'signature verification failed')
        t.end()
      })
    })
  })
})

test('globalSignature altered', function (t) {
  fs.readFile('./fixtures/wrongGlobalSig.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)

        t.throws(() => minisign.verifySignature(signature, content, PKinfo), 'trusted comment cannot be verified')
        t.end()
      })
    })
  })
})

test('emoji trusted comment', function (t) {
  fs.readFile('./fixtures/emojiComment.txt.minisig', function (err, signature) {
    t.error(err)
    fs.readFile('./fixtures/example.txt', function (err, content) {
      t.error(err)
      fs.readFile('./fixtures/minisign.pub', function (err, publicKeyBuf) {
        t.error(err)
        var PKinfo = minisign.parsePubKey(publicKeyBuf)
        t.ok(minisign.verifySignature(signature, content, PKinfo))
        t.end()
      })
    })
  })
})

test.only('signContent generated input', function (t) {
  var toSign = Buffer.alloc(200)
  sodium.randombytes_buf(toSign)

  fs.readFile('./fixtures/minisign.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey('', SKinfo)

    var signedOutput = minisign.signContent(toSign, SKdetails).outputBuf

    fs.readFile('./fixtures/minisign.pub', function (err, PK) {
      t.error(err)
      var PKinfo = minisign.parsePubKey(PK)
      t.ok(minisign.verifySignature(signedOutput, toSign, PKinfo))
      t.end()
    })
  })
})

// for reference
function verifySignature (signedContent, originalContent, publicKeyInfo) {
  var contentSigned
  var signature = parseSignature(signedContent)
  if (signature.signatureAlgorithm.toString() === 'ED') {
    var hashedContent = Buffer.alloc(sodium.crypto_generichash_BYTES_MAX)
    sodium.crypto_generichash(hashedContent, originalContent)
    contentSigned = hashedContent
  } else {
    contentSigned = originalContent
  }

  if (!(signature.keyID.equals(publicKeyInfo.keyID))) {
    return ("error: keyID's do not match")
  } else {
    if (!(sodium.crypto_sign_verify_detached(signature.signature, contentSigned, publicKeyInfo.publicKey))) {
      return ('error: signature verification failed')
    } else {
      var forGlobalSig = Buffer.concat([signature.signature, Buffer.from(signature.trustedComment)])
      if (!(sodium.crypto_sign_verify_detached(signature.globalSignature, forGlobalSig, publicKeyInfo.publicKey))) {
        return ('error: trusted comment cannot be verified')
      }
    }
  }
  return ('signature and comment successfully verified')
}