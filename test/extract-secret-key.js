var test = require('tape')
var minisign = require('../minisign.js')
var fs = require('fs')
var sodium = require('sodium-native')

test('key generated with no password', function (t) {
  var noString = ''
  fs.readFile('./test/fixtures/no-string.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(noString, SKinfo)
    fs.readFile('./test/fixtures/no-string.pub', function (err, PK) {
      t.error(err)
      var publicKeyID = minisign.parsePubKey(PK).keyID

      t.equal(SKdetails.secretKey.byteLength, sodium.crypto_sign_SECRETKEYBYTES)
      t.deepEqual(SKdetails.keyID, publicKeyID)
      t.equal(SKdetails.signatureAlgorithm, 'Ed')
      t.end()
    })
  })
})

test('key generated with emoji password', function (t) {
  var emojiString = 'testing👫'
  fs.readFile('./test/fixtures/emoji-string.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(emojiString, SKinfo)
    fs.readFile('./test/fixtures/emoji-string.pub', function (err, PK) {
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
test('key generated with long password [180KB]', function (t) {
  fs.readFile('./test/fixtures/long-comment.pub', function (err, data) {
    t.error(err)
    var password = data
    fs.readFile('./test/fixtures/long-pwd.key', function (err, SK) {
      t.error(err)
      var SKinfo = minisign.parseSecretKey(SK)
      var SKdetails = minisign.extractSecretKey(password, SKinfo)
      fs.readFile('./test/fixtures/long-pwd.pub', function (err, PK) {
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

test('using too small kdfOpsLimit', function (t) {
  var noString = ''
  fs.readFile('./test/fixtures/no-string.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    SKinfo.kdfOpsLimit--

    t.throws(() => minisign.extractSecretKey(noString, SKinfo), '[ERR_ASSERTION]')
    t.end()
  })
})

test('using too small kdfMemLimit', function (t) {
  var noString = ''
  fs.readFile('./test/fixtures/no-string.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    SKinfo.kdfMemLimit--

    t.throws(() => minisign.extractSecretKey(noString, SKinfo), '[ERR_ASSERTION]')
    t.end()
  })
})

test('invalid input - missing salt', function (t) {
  var noString = ''
  fs.readFile('./test/fixtures/no-string.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    delete SKinfo.kdfSalt

    t.throws(() => minisign.extractSecretKey(noString, SKinfo))
    t.end()
  })
})

test('wrong kdfSalt', function (t) {
  var noString = ''
  fs.readFile('./test/fixtures/no-string.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    SKinfo.kdfSalt++

    t.throws(() => minisign.extractSecretKey(noString, SKinfo), '[ERR_ASSERTION]')
    t.end()
  })
})

test('keypairGen output', function (t) {
  var keyGen = minisign.keypairGen('')
  var key = minisign.formatKeys(keyGen)

  var PKiD = minisign.parsePubKey(key.PK).keyID
  var SKinfo = minisign.parseSecretKey(key.SK)
  var SK = minisign.extractSecretKey('', SKinfo)

  t.equal(SK.secretKey.byteLength, sodium.crypto_sign_SECRETKEYBYTES)
  t.deepEqual(SK.keyID, PKiD)
  t.equal(SK.signatureAlgorithm, 'Ed')
  t.end()
})
