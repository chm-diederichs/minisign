const fs = require('fs')
const assert = require('assert')
const sodium = require('sodium-native')
const xor = require('buffer-xor')
const reverse = require('buffer-reverse')

// put path for file to be signed and signature file here
const file = 'test.txt'
const signatureFile = `${file}.minisig`
const pubKeyFile = 'minisign.pub'
const secKeyFile = 'minisign.key'
const comment = '<insert comment here>'

const untrustedPrelude = Buffer.from('untrusted comment: ')
const trustedPrelude = Buffer.from('trusted comment: ')
const untrustedCommentStart = untrustedPrelude.byteLength
const expectedSignatureAlgorithm = Buffer.from('Ed')

// password for kdf algorithm - must correspond to the minisign public key
const passwordBuf = Buffer.from('')

function parsePubkey (pubkeyBuf) {
  assert(untrustedPrelude.equals(pubkeyBuf.subarray(0, untrustedCommentStart)))
  const untrustedComment = pubkeyBuf.subarray(untrustedCommentStart, pubkeyBuf.indexOf('\n', untrustedCommentStart))

  const keyInfoStart = untrustedCommentStart + untrustedComment.byteLength + 1
  const keyInfoBase64 = pubkeyBuf.subarray(keyInfoStart, pubkeyBuf.indexOf('\n', keyInfoStart)).toString()
  const keyInfo = Buffer.from(keyInfoBase64, 'base64')

  const signatureAlgorithm = keyInfo.subarray(0, 2)
  const keyId = reverse(keyInfo.subarray(2, 10)).toString('hex')
  const publicKey = keyInfo.subarray(10)

  assert(signatureAlgorithm.equals(expectedSignatureAlgorithm))

  return {
    untrustedComment,
    signatureAlgorithm,
    keyId,
    publicKey
  }
}

function parseSignature (signatureBuf) {
  assert(untrustedPrelude.equals(signatureBuf.subarray(0, untrustedCommentStart)))

  const untrustedCommentEnd = signatureBuf.indexOf('\n', untrustedCommentStart)
  const untrustedComment = signatureBuf.subarray(untrustedCommentStart, untrustedCommentEnd)

  const sigInfoStart = untrustedCommentEnd + 1
  const sigInfoEnd = signatureBuf.indexOf('\n', sigInfoStart)
  const sigInfoBase64 = signatureBuf.subarray(sigInfoStart, sigInfoEnd).toString()
  const sigInfo = Buffer.from(sigInfoBase64, 'base64')

  const signatureAlgorithm = sigInfo.subarray(0, 2)
  const keyId = reverse(sigInfo.subarray(2, 10))
  const signature = sigInfo.subarray(10, sigInfoEnd)

  const trustedCommentStart = sigInfoEnd + 1 + trustedPrelude.byteLength
  const trustedCommentEnd = signatureBuf.indexOf('\n', trustedCommentStart)
  const trustedComment = signatureBuf.subarray(trustedCommentStart, trustedCommentEnd)

  const globalSignatureBase64 = signatureBuf.subarray(trustedCommentEnd + 1)
  const globalSignature = Buffer.from(globalSignatureBase64, 'base64')

  return {
    untrustedComment,
    signatureAlgorithm,
    keyId,
    signature,
    trustedComment,
    globalSignature
  }
}

function parseSecretKey (secretKeyBuf) {
  assert(untrustedPrelude.equals(secretKeyBuf.subarray(0, untrustedCommentStart)))

  const untrustedCommentEnd = secretKeyBuf.indexOf('\n', untrustedCommentStart)
  const untrustedComment = secretKeyBuf.subarray(untrustedCommentStart, untrustedCommentEnd).toString('ascii')

  const secretKeyInfoStart = untrustedCommentEnd + 1
  const secretKeyInfoEnd = secretKeyBuf.indexOf('\n', secretKeyInfoStart)
  const secretKeyInfoBase64 = secretKeyBuf.subarray(secretKeyInfoStart, secretKeyInfoEnd).toString()
  const secretKeyInfo = Buffer.from(secretKeyInfoBase64, 'base64')

  const signatureAlgorithm = secretKeyInfo.subarray(0, 2).toString()
  const kdfAlgorithm = secretKeyInfo.subarray(2, 4).toString()
  const cksumAlgorithm = secretKeyInfo.subarray(4, 6).toString()
  const kdfSalt = secretKeyInfo.subarray(6, 38)
  const kdfOpsLimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
  const kdfMemLimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE
  const keynumSK = secretKeyInfo.subarray(secretKeyInfo.length - 104)

  return {
    untrustedComment,
    signatureAlgorithm,
    kdfAlgorithm,
    cksumAlgorithm,
    kdfSalt,
    kdfOpsLimit,
    kdfMemLimit,
    keynumSK
  }
}

function extractSecretKey (passwordBuf, kdfSalt, kdfOpsLimit, kdfMemLimit, keynumSK) {
  var kdfOutput = Buffer.alloc(104)
  var keynumInfo = Buffer.alloc(104)

  sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, passwordBuf, kdfSalt, kdfOpsLimit, kdfMemLimit)
  keynumInfo = xor(kdfOutput, keynumSK)
  const keyID = keynumInfo.subarray(0, 8)
  const secretKey = keynumInfo.subarray(8, 72)
  const checksum = keynumInfo.subarray(72)

  return {
    keyID,
    secretKey,
    checksum
  }
}

// load secret key file
fs.readFile(secKeyFile, function (err, SKbuf) {
  if (err) throw err
  var SKinfo = parseSecretKey(SKbuf)
  SKinfo = extractSecretKey(passwordBuf, SKinfo.kdfSalt, SKinfo.kdfOpsLimit, SKinfo.kdfMemLimit, SKinfo.keynumSK)

  var signatureTest = Buffer.alloc(sodium.crypto_sign_BYTES)
  var globalSignatureTest = Buffer.alloc(sodium.crypto_sign_BYTES)
  console.log(SKinfo.keyID)

  // load content to be signed
  fs.readFile(file, function (err, message) {
    if (err) throw err
    sodium.crypto_sign_detached(signatureTest, message, SKinfo.secretKey)
    var forGlobalSig = Buffer.concat([signatureTest, Buffer.from(comment)])
    sodium.crypto_sign_detached(globalSignatureTest, forGlobalSig, SKinfo.secretKey)
    var toFile = ('untrusted comment: \n' + Buffer.concat([expectedSignatureAlgorithm, SKinfo.keyID, signatureTest]).toString('base64') + '\n' + 'trusted comment: ' + comment.toString('ascii') + '\n' + globalSignatureTest.toString('base64'))
    console.log(toFile)

    // write signature to file
    fs.writeFile(signatureFile, toFile, function (err) {
      if (err) throw err
      console.log(`minsign signature saved to ${signatureFile}`)
    })
  })
})
