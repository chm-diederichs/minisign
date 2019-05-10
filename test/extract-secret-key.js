var test = require('tape')
var minisign = require('../minisign.js')
var fs = require('fs')
var sodium = require('sodium-native')

test('key generated with no password', (t) => {
  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)
  fs.readFile('./test/fixtures/no-string.key', (err, SK) => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(pwd, SKinfo)
    fs.readFile('./test/fixtures/no-string.pub', (err, PK) => {
      t.error(err)
      var publicKeyID = minisign.parsePubKey(PK).keyID

      t.equal(SKdetails.secretKey.byteLength, sodium.crypto_sign_SECRETKEYBYTES)
      t.deepEqual(SKdetails.keyID, publicKeyID)
      t.equal(SKdetails.signatureAlgorithm, 'Ed')
      t.end()
    })
  })
})

test('key generated with emoji password', (t) =>{
  var emojiBuf = Buffer.from('testing👫')
  var pwd = sodium.sodium_malloc(emojiBuf.byteLength)
  pwd.fill(emojiBuf)
  fs.readFile('./test/fixtures/emoji-string.key', (err, SK) =>{
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(pwd, SKinfo)
    fs.readFile('./test/fixtures/emoji-string.pub', (err, PK) =>{
      t.error(err)
      var publicKeyID = minisign.parsePubKey(PK).keyID

      t.equal(SKdetails.secretKey.byteLength, sodium.crypto_sign_SECRETKEYBYTES)
      t.deepEqual(SKdetails.keyID, publicKeyID)
      t.equal(SKdetails.signatureAlgorithm, 'Ed')
      t.end()
    })
  })
})

// cannot use password this long via minisign in terminal
test('key generated with long password [180KB]', (t) => {
  fs.readFile('./test/fixtures/long-comment.pub', (err, data) => {
    t.error(err)
    var pwd = sodium.sodium_malloc(data.byteLength)
    pwd.fill(data)
    fs.readFile('./test/fixtures/long-pwd.key', (err, SK) => {
      t.error(err)
      var SKinfo = minisign.parseSecretKey(SK)
      var SKdetails = minisign.extractSecretKey(pwd, SKinfo)
      fs.readFile('./test/fixtures/long-pwd.pub', (err, PK) => {
        t.error(err)
        var publicKeyID = minisign.parsePubKey(PK).keyID

        t.equal(SKdetails.secretKey.byteLength, sodium.crypto_sign_SECRETKEYBYTES)
        t.deepEqual(SKdetails.keyID, publicKeyID)
        t.equal(SKdetails.signatureAlgorithm, 'Ed')
        t.end()
      })
    })
  })
})

test('using too small kdfOpsLimit', (t) => {
  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)
  fs.readFile('./test/fixtures/no-string.key', (err, SK) => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    SKinfo.kdfOpsLimit--

    t.throws(() => minisign.extractSecretKey(pwd, SKinfo), 'invalid check sum')
    t.end()
  })
})

test('using too small kdfMemLimit', (t) => {
  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)
  fs.readFile('./test/fixtures/no-string.key', (err, SK) => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    SKinfo.kdfMemLimit--

    t.throws(() => minisign.extractSecretKey(pwd, SKinfo), 'invalid check sum')
    t.end()
  })
})

test('invalid input - missing salt', (t) => {
  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)
  fs.readFile('./test/fixtures/no-string.key', (err, SK) => => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    delete SKinfo.kdfSalt

    t.throws(() => minisign.extractSecretKey(pwd, SKinfo))
    t.end()
  })
})

test('wrong kdfSalt', (t) => {
  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)
  fs.readFile('./test/fixtures/no-string.key', (err, SK) => {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    SKinfo.kdfSalt++

    t.throws(() => minisign.extractSecretKey(pwd, SKinfo), 'invalid check sum')
    t.end()
  })
})

test('keypairGen output', (t) => {
  var emptyBuf = Buffer.from('')
  var pwd = sodium.sodium_malloc(emptyBuf.byteLength)
  pwd.fill(emptyBuf)
  var keyGen = minisign.keypairGen(pwd)
  var key = minisign.formatKeys(keyGen)

  var PKiD = minisign.parsePubKey(key.PK).keyID
  var SKinfo = minisign.parseSecretKey(key.SK)
  var SK = minisign.extractSecretKey(pwd, SKinfo)

  t.equal(SK.secretKey.byteLength, sodium.crypto_sign_SECRETKEYBYTES)
  t.deepEqual(SK.keyID, PKiD)
  t.equal(SK.signatureAlgorithm, 'Ed')
  t.end()
})
