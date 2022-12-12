const assert = require('assert')
const sodium = require('sodium-native')
const xor = require('buffer-xor')

const defaultComment = 'signature from minisign secret key'
const untrustedPrelude = Buffer.from('untrusted comment: ')
const trustedPrelude = Buffer.from('trusted comment: ')
const untrustedCommentStart = untrustedPrelude.byteLength

// parse public key data saved to file in minisign format
function parsePubKey (pubkeyBuf) {
  assert(untrustedPrelude.equals(pubkeyBuf.subarray(0, untrustedCommentStart)), 'file format not recognised')
  const untrustedCommentEnd = pubkeyBuf.indexOf('\n', untrustedCommentStart)
  const untrustedComment = pubkeyBuf.subarray(untrustedCommentStart, untrustedCommentEnd)

  const keyInfoStart = untrustedCommentStart + untrustedComment.byteLength + 1
  const keyInfoBase64 = pubkeyBuf.subarray(keyInfoStart, pubkeyBuf.indexOf('\n', keyInfoStart)).toString()
  const keyInfo = Buffer.from(keyInfoBase64, 'base64')

  const signatureAlgorithm = keyInfo.subarray(0, 2)
  const keyID = keyInfo.subarray(2, 10)
  const publicKey = keyInfo.subarray(10)
  assert(publicKey.byteLength === (sodium.crypto_sign_PUBLICKEYBYTES), 'invalid public key given')
  assert(keyInfoStart === pubkeyBuf.length - 57, 'file format not recognised')

  return {
    untrustedComment,
    signatureAlgorithm,
    keyID,
    publicKey
  }
}

// parse key directly from command line
function parseKeyCLI (pubKeyString) {
  const keyInfo = Buffer.from(pubKeyString, 'base64')

  const signatureAlgorithm = keyInfo.subarray(0, 2)
  const keyID = keyInfo.subarray(2, 10)
  const publicKey = keyInfo.subarray(10)
  assert(publicKey.byteLength === (sodium.crypto_sign_PUBLICKEYBYTES), 'invalid public key given')

  return {
    signatureAlgorithm,
    keyID,
    publicKey
  }
}

// takes signature buffer and returns info as buffers
function parseSignature (signatureBuf) {
  assert(untrustedPrelude.equals(signatureBuf.subarray(0, untrustedCommentStart)), 'file format not recognised')

  const untrustedCommentEnd = signatureBuf.indexOf('\n', untrustedCommentStart)
  const untrustedComment = signatureBuf.subarray(untrustedCommentStart, untrustedCommentEnd)

  const sigInfoStart = untrustedCommentEnd + 1
  const sigInfoEnd = signatureBuf.indexOf('\n', sigInfoStart)
  const sigInfoBase64 = signatureBuf.subarray(sigInfoStart, sigInfoEnd).toString()
  const sigInfo = Buffer.from(sigInfoBase64, 'base64')

  const signatureAlgorithm = sigInfo.subarray(0, 2)
  const keyID = sigInfo.subarray(2, 10)
  const signature = sigInfo.subarray(10, sigInfoEnd)

  const trustedCommentStart = sigInfoEnd + 1 + trustedPrelude.byteLength
  const trustedCommentEnd = signatureBuf.indexOf('\n', trustedCommentStart)
  const trustedComment = signatureBuf.subarray(trustedCommentStart, trustedCommentEnd)

  assert(signatureBuf.subarray(sigInfoEnd + 1, trustedCommentStart).equals(trustedPrelude), 'file format not recognised')
  assert(trustedCommentEnd === signatureBuf.length - 90, 'file format not recognised')

  const globalSignatureBase64 = signatureBuf.subarray(trustedCommentEnd + 1).toString()
  const globalSignature = Buffer.from(globalSignatureBase64, 'base64')

  return {
    untrustedComment,
    signatureAlgorithm,
    keyID,
    signature,
    trustedComment,
    globalSignature
  }
}

// takes encrypted secret key buffer and returns info as buffers
function parseSecretKey (secretKeyBuf) {
  assert(untrustedPrelude.equals(secretKeyBuf.subarray(0, untrustedCommentStart)), 'file format not recognised')

  const untrustedCommentEnd = secretKeyBuf.indexOf('\n', untrustedCommentStart)
  const untrustedComment = secretKeyBuf.subarray(untrustedCommentStart, untrustedCommentEnd).toString()

  const secretKeyInfoStart = untrustedCommentEnd + 1
  const secretKeyInfoEnd = secretKeyBuf.indexOf('\n', secretKeyInfoStart)
  const secretKeyInfoBase64 = secretKeyBuf.subarray(secretKeyInfoStart, secretKeyInfoEnd)
  const secretKeyInfo = Buffer.from(secretKeyInfoBase64.toString(), 'base64')
  assert(secretKeyInfoBase64.length === 212, 'base64 conversion failed, was an actual secret key given?')

  const signatureAlgorithm = secretKeyInfo.subarray(0, 2)
  const kdfAlgorithm = secretKeyInfo.subarray(2, 4)
  const cksumAlgorithm = secretKeyInfo.subarray(4, 6)
  const kdfSalt = secretKeyInfo.subarray(6, 38)
  const kdfOpsLimit = secretKeyInfo.readUInt32LE(38)
  const kdfMemLimit = secretKeyInfo.readUInt32LE(46)
  const keynumSK = secretKeyInfo.subarray(secretKeyInfo.length - 104)

  assert(secretKeyInfoEnd === secretKeyBuf.length - 1, 'file format not recognised')

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

// takes output from parseSecretKey() and decrypts secret key
function extractSecretKey (pwd, parsedSK) {
  var kdfOutput = Buffer.alloc(104)
  var keynumInfo
  var sumCheck = Buffer.alloc(sodium.crypto_generichash_BYTES)
  var opsLimit = parsedSK.kdfOpsLimit
  var memLimit = parsedSK.kdfMemLimit
  var salt = parsedSK.kdfSalt

  sodium.sodium_mprotect_readwrite(pwd)
  sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, pwd, salt, opsLimit, memLimit)
  sodium.sodium_memzero(pwd)
  sodium.sodium_mprotect_noaccess(pwd)

  const secretKey = sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES)
  keynumInfo = xor(kdfOutput, parsedSK.keynumSK)
  const keyID = keynumInfo.subarray(0, 8)
  secretKey.fill(keynumInfo.subarray(8, 72))
  const checkSum = keynumInfo.subarray(72)
  const signatureAlgorithm = parsedSK.signatureAlgorithm.toString()

  var sumCheckData = Buffer.concat([parsedSK.signatureAlgorithm, keyID, secretKey])
  sodium.sodium_mprotect_noaccess(secretKey)

  sodium.crypto_generichash(sumCheck, sumCheckData)
  assert(sumCheck.equals(checkSum), 'invalid check sum')

  return {
    keyID,
    secretKey,
    sumCheck,
    checkSum,
    signatureAlgorithm
  }
}

// takes arbitrary content buffer and returns signature buffer in minisgn format
function signContent (content, SKdetails, opts) {
  if (opts == null) opts = {}
  var comment = opts.comment || defaultComment
  var tComment = opts.tComment || (Math.floor(Date.now() / 1000)).toString('10')
  var sigAlgorithm = Buffer.from(opts.sigAlgorithm || 'ED')
  var contentToSign
  var signatureAlgorithm
  var trustComment

  if (sigAlgorithm.equals(Buffer.from('ED'))) {
    var hashedContent = Buffer.alloc(sodium.crypto_generichash_BYTES_MAX)
    sodium.crypto_generichash(hashedContent, content)
    contentToSign = hashedContent
    signatureAlgorithm = Buffer.from(sigAlgorithm)
  } else {
    assert(sigAlgorithm.equals(Buffer.from('Ed')), 'algorithm not recognised')
    contentToSign = content
    signatureAlgorithm = Buffer.from(SKdetails.signatureAlgorithm)
  }

  var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  var globalSignature = Buffer.alloc(sodium.crypto_sign_BYTES)

  sodium.sodium_mprotect_readwrite(SKdetails.secretKey)
  sodium.crypto_sign_detached(signature, contentToSign, SKdetails.secretKey)

  var signatureInfo = Buffer.concat([signatureAlgorithm, SKdetails.keyID, signature])
  var untrustedComment = Buffer.from('untrusted comment: ' + comment + '\n')
  var trustedComment = Buffer.from('\ntrusted comment: ' + tComment + '\n')
  var sigInfoBase64 = Buffer.from(signatureInfo.toString('base64'))

  var forGlobalSig = Buffer.concat([signature, Buffer.from(tComment)])
  sodium.crypto_sign_detached(globalSignature, forGlobalSig, SKdetails.secretKey)
  sodium.sodium_memzero(SKdetails.secretKey)
  sodium.sodium_mprotect_noaccess(SKdetails.secretKey)

  var globalSigBase64 = Buffer.from(globalSignature.toString('base64') + '\n')

  var outputBuf = Buffer.concat([untrustedComment, sigInfoBase64, trustedComment, globalSigBase64])

  return {
    outputBuf,
    untrustedComment,
    sigInfoBase64,
    trustComment,
    globalSigBase64
  }
}

// verify the signature of a parsed input buffer
function verifySignature (signature, originalContent, publicKeyInfo) {
  var contentSigned
  if (signature.signatureAlgorithm.equals(Buffer.from('ED'))) {
    var hashedContent = Buffer.alloc(sodium.crypto_generichash_BYTES_MAX)
    sodium.crypto_generichash(hashedContent, originalContent)
    contentSigned = hashedContent
  } else {
    contentSigned = originalContent
  }

  if (!(signature.keyID.equals(publicKeyInfo.keyID))) {
    throw new Error("keyID's do not match")
  } else {
    if (!(sodium.crypto_sign_verify_detached(signature.signature, contentSigned, publicKeyInfo.publicKey))) {
      throw new Error('signature verification failed')
    } else {
      var forGlobalSig = Buffer.concat([signature.signature, Buffer.from(signature.trustedComment)])
      if (!(sodium.crypto_sign_verify_detached(signature.globalSignature, forGlobalSig, publicKeyInfo.publicKey))) {
        throw new Error('trusted comment cannot be verified')
      }
    }
  }
  return true
}

// generate new key pair
function keypairGen (pwd, opts) {
  var keyID = Buffer.alloc(8)
  sodium.randombytes_buf(keyID)

  var PKdComment = 'minisign public key ' + keyID.toString('hex').toUpperCase()
  var SKdComment = 'minisign encrypted secret key'

  if (opts == null) opts = {}
  var PKcomment = opts.PKcomment || PKdComment
  var SKcomment = opts.SKcomment || SKdComment
  var sigAlgorithm = Buffer.from(opts.sigAlgorithm || 'Ed')
  var kdfAlgorithm = Buffer.from(opts.kdfAlgorithm || 'Sc')
  var cksumAlgorithm = Buffer.from(opts.cksumAlgorithm || 'B2')

  var kdfSalt = Buffer.alloc(32)
  var kdfOutput = Buffer.alloc(104)

  var publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  var secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  var checkSum = Buffer.alloc(sodium.crypto_generichash_BYTES)

  sodium.randombytes_buf(kdfSalt)
  sodium.crypto_sign_keypair(publicKey, secretKey)

  const kdfOpsLimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
  const kdfMemLimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE
  var kdfLimits = Buffer.alloc(16)
  kdfLimits.writeUInt32LE(kdfOpsLimit, 0)
  kdfLimits.writeUInt32LE(kdfMemLimit, 8)

  var checkSumData = Buffer.concat([sigAlgorithm, keyID, secretKey])
  sodium.crypto_generichash(checkSum, checkSumData)

  var keynumData = Buffer.concat([keyID, secretKey, checkSum])
  sodium.sodium_mprotect_readwrite(pwd)
  sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, pwd, kdfSalt, kdfOpsLimit, kdfMemLimit)
  sodium.sodium_memzero(pwd)
  sodium.sodium_mprotect_noaccess(pwd)
  var keynumSK = xor(kdfOutput, keynumData)

  return {
    publicKey,
    sigAlgorithm,
    keyID,
    kdfAlgorithm,
    cksumAlgorithm,
    kdfSalt,
    kdfLimits,
    keynumSK,
    SKcomment,
    PKcomment
  }
}

// format keys to be saved to file in minisign compatible format
function formatKeys (keyGen) {
  var sigAlgorithm = keyGen.sigAlgorithm
  var kdfAlgorithm = keyGen.kdfAlgorithm
  var cksumAlgorithm = keyGen.cksumAlgorithm
  var kdfSalt = keyGen.kdfSalt
  var kdfLimits = keyGen.kdfLimits
  var keynumSK = keyGen.keynumSK

  var PKfullComment = 'untrusted comment: ' + keyGen.PKcomment + '\n'
  var SKfullComment = 'untrusted comment: ' + keyGen.SKcomment + '\n'

  var SKalgorithmInfo = Buffer.from(sigAlgorithm + kdfAlgorithm + cksumAlgorithm)

  var SKinfo = Buffer.concat([SKalgorithmInfo, kdfSalt, kdfLimits, keynumSK]).toString('base64') + '\n'
  var PKinfo = Buffer.concat([sigAlgorithm, keyGen.keyID, keyGen.publicKey]).toString('base64') + '\n'

  var SK = Buffer.from(SKfullComment + SKinfo)
  var PK = Buffer.from(PKfullComment + PKinfo)

  return {
    PK,
    SK
  }
}

module.exports = {
  parsePubKey: parsePubKey,
  parseSignature: parseSignature,
  parseSecretKey: parseSecretKey,
  extractSecretKey: extractSecretKey,
  signContent: signContent,
  verifySignature: verifySignature,
  keypairGen: keypairGen,
  formatKeys: formatKeys,
  parseKeyCLI: parseKeyCLI
}
