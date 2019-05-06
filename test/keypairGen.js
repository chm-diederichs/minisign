var test = require('tape')
var minisign = require('../minisign')
var fs = require('fs')

test('key generation with empty password', function (t) {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength

  var noStringPwdKey = minisign.keypairGen('')

  var SKoutput = noStringPwdKey.SKoutputBuffer
  var PKoutput = noStringPwdKey.PKoutputBuffer
  var PKinfo = Buffer.from(PKoutput.slice(-57, -1).toString(), 'base64')

  t.deepEqual(PKoutput.subarray(0, endIndex), untrustedPrelude)
  t.deepEqual(SKoutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./fixtures/noString.key', function (err, SKinfo) {
    t.error(err)
    t.equal(SKoutput.byteLength, SKinfo.byteLength)
    t.deepEqual(noStringPwdKey.publicKey, PKinfo.subarray(-32))
    t.end()
  })
})

test('key generation with string password', function (t) {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength

  var stringPwdKey = minisign.keypairGen('testing')

  var SKoutput = stringPwdKey.SKoutputBuffer
  var PKoutput = stringPwdKey.PKoutputBuffer
  var PKinfo = Buffer.from(PKoutput.slice(-57, -1).toString(), 'base64')

  t.deepEqual(PKoutput.subarray(0, endIndex), untrustedPrelude)
  t.deepEqual(SKoutput.subarray(0, endIndex), untrustedPrelude)

  fs.readFile('./fixtures/string.key', function (err, SKinfo) {
    t.error(err)
    t.equal(SKoutput.byteLength, SKinfo.byteLength)
    t.deepEqual(stringPwdKey.publicKey, PKinfo.subarray(-32))
    t.end()
  })
})

test('key generation with emoji password', function (t) {
  const untrustedPrelude = Buffer.from('untrusted comment: ')
  var endIndex = untrustedPrelude.byteLength

  var emojiPwdKey = minisign.keypairGen('testing👫')

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

function keypairGen (pwd, opts) {
  var keyID = Buffer.alloc(8)
  sodium.randombytes_buf(keyID)

  var PKdComment = 'minisign public key' + keyID.toString('hex').toUpperCase()
  var SKdComment = 'minisign encrypted secret key'

  if (opts == null) opts = {}
  var PKcomment = opts.PKcomment || opts.SKcomment || PKdComment
  var SKcomment = opts.SKcomment || opts.PKcomment || SKdComment
  var sigAlgorithm = opts.sigAlgorithm || 'Ed'
  var kdfAlgorithm = opts.kdfAlgorithm || 'Sc'
  var cksumAlgorithm = opts.cksumAlgorithm || 'B2'

  var kdfSalt = Buffer.alloc(32)
  var kdfOutput = Buffer.alloc(104)

  var publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  var secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  var checkSum = Buffer.alloc(sodium.crypto_generichash_BYTES)

  sodium.randombytes_buf(kdfSalt)
  sodium.crypto_sign_keypair(publicKey, secretKey)

  var PKfullComment = 'untrusted comment: ' + PKcomment + '\n'
  var SKfullComment = 'untrusted comment: ' + SKcomment + '\n'

  const kdfOpsLimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
  const kdfMemLimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE
  var kdfLimits = Buffer.alloc(16)
  kdfLimits.writeUInt32LE(kdfOpsLimit, 0)
  kdfLimits.writeUInt32LE(kdfMemLimit, 8)

  var checkSumData = Buffer.concat([Buffer.from(sigAlgorithm), keyID, secretKey])
  sodium.crypto_generichash(checkSum, checkSumData)

  var keynumData = Buffer.concat([keyID, secretKey, checkSum])
  sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, Buffer.from(pwd), kdfSalt, kdfOpsLimit, kdfMemLimit)
  var keynumSK = xor(kdfOutput, keynumData)

  var SKalgorithmInfo = Buffer.from(sigAlgorithm + kdfAlgorithm + cksumAlgorithm)

  var SKinfo = Buffer.concat([SKalgorithmInfo, kdfSalt, kdfLimits, keynumSK]).toString('base64') + '\n'
  var PKinfo = Buffer.concat([Buffer.from(sigAlgorithm), keyID, publicKey]).toString('base64') + '\n'

  var SKoutputBuffer = Buffer.from(SKfullComment + SKinfo)
  var PKoutputBuffer = Buffer.from(PKfullComment + PKinfo)

  return {
    publicKey,
    sigAlgorithm,
    keyID,
    SKinfo,
    PKoutputBuffer,
    SKoutputBuffer
  }
}

// have to add test for no comment provided. have to rewrite tests. --> now test PKoutput and SKoutput.
// now need to test all options combinations.
