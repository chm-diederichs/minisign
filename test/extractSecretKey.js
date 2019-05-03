var test = require('tape')
var minisign = require('../minisign.js')
var fs = require('fs')
var sodium = require('sodium-native')

test.only('key generated with no password', function (t) {
  var noString = ''
  fs.readFile('./fixtures/noString.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(noString, SKinfo)
    console.log(SKdetails.keyID)
    fs.readFile('./fixtures/noString.pub', function (err, PK) {
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
  fs.readFile('./fixtures/emojiString.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    var SKdetails = minisign.extractSecretKey(emojiString, SKinfo)
    fs.readFile('./fixtures/emojiString.pub', function (err, PK) {
      t.error(err)
      var publicKeyID = minisign.parsePubkey(PK).keyID

      t.equal(SKdetails.secretKey.byteLength, sodium.crypto_sign_SECRETKEYBYTES)
      t.deepEqual(SKdetails.keyID, publicKeyID)
      t.equal(SKdetails.signatureAlgorithm, 'Ed')
      t.end()
    })
  })
})

// cannot use password this long via minisign in terminal
test('key generated with long password [180KB]', function (t) {
  fs.readFile('./fixtures/longComment.pub', function (err, data) {
    t.error(err)
    var password = data
    fs.readFile('./fixtures/longPwd.key', function (err, SK) {
      t.error(err)
      var SKinfo = minisign.parseSecretKey(SK)
      var SKdetails = minisign.extractSecretKey(password, SKinfo)
      fs.readFile('./fixtures/longPwd.pub', function (err, PK) {
        t.error(err)
        var publicKeyID = minisign.parsePubkey(PK).keyID

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
  fs.readFile('./fixtures/noString.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    SKinfo.kdfOpsLimit--

    t.throws(() => minisign.extractSecretKey(noString, SKinfo), '[ERR_ASSERTION]')
    t.end()
  })
})

test('using too small kdfMemLimit', function (t) {
  var noString = ''
  fs.readFile('./fixtures/noString.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    SKinfo.kdfMemLimit--

    t.throws(() => minisign.extractSecretKey(noString, SKinfo), '[ERR_ASSERTION]')
    t.end()
  })
})

test('invalid input - missing salt', function (t) {
  var noString = ''
  fs.readFile('./fixtures/noString.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    delete SKinfo.kdfSalt

    t.throws(() => minisign.extractSecretKey(noString, SKinfo))
    t.end()
  })
})

test('wrong kdfSalt', function (t) {
  var noString = ''
  fs.readFile('./fixtures/noString.key', function (err, SK) {
    t.error(err)
    var SKinfo = minisign.parseSecretKey(SK)
    SKinfo.kdfSalt++

    t.throws(() => minisign.extractSecretKey(noString, SKinfo), '[ERR_ASSERTION]')
    t.end()
  })
})
// cases: wrong algorithm?

// for reference
function extractSecretKey (pwd, SKinfo) {
  var kdfOutput = Buffer.alloc(104)
  var keynumInfo
  var sumCheck = Buffer.alloc(sodium.crypto_generichash_BYTES)
  var opsLimit = SKinfo.kdfOpsLimit
  var memLimit = SKinfo.kdfMemLimit
  var salt = SKinfo.kdfSalt
  var sigAlgorithm = Buffer.from(SKinfo.signatureAlgorithm)

  sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, pwd, salt, opsLimit, memLimit)
  keynumInfo = xor(kdfOutput, SKinfo.keynumSK)
  const keyID = keynumInfo.subarray(0, 8)
  const secretKey = keynumInfo.subarray(8, 72)
  const checkSum = keynumInfo.subarray(72)
  const signatureAlgorithm = SKinfo.signatureAlgorithm

  var sumCheckData = Buffer.concat([sigAlgorithm, keyID, secretKey])
  sodium.crypto_generichash(sumCheck, sumCheckData)

  assert(sumCheck.equals(checkSum))

  return {
    keyID,
    secretKey,
    sumCheck,
    checkSum,
    signatureAlgorithm
  }
}
