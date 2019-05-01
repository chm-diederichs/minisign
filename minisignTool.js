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
var comment = '<insert comment here>'
var trustedComment = '<insert trusted comment here>'

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
  const keyID = reverse(keyInfo.subarray(2, 10))
  const publicKey = keyInfo.subarray(10)

  assert(signatureAlgorithm.equals(expectedSignatureAlgorithm))

  return {
    untrustedComment,
    signatureAlgorithm,
    keyID,
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
  const keyID = reverse(sigInfo.subarray(2, 10))
  const signature = sigInfo.subarray(10, sigInfoEnd)

  const trustedCommentStart = sigInfoEnd + 1 + trustedPrelude.byteLength
  const trustedCommentEnd = signatureBuf.indexOf('\n', trustedCommentStart)
  const trustedComment = signatureBuf.subarray(trustedCommentStart, trustedCommentEnd)

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

function extractSecretKey (passwordBuf, SKinfo) {
  var kdfOutput = Buffer.alloc(104)
  var keynumInfo
  var ckSum = Buffer.alloc(sodium.crypto_generichash_BYTES)

  sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, passwordBuf, SKinfo.kdfSalt, SKinfo.kdfOpsLimit, SKinfo.kdfMemLimit)
  keynumInfo = xor(kdfOutput, SKinfo.keynumSK)
  const keyID = keynumInfo.subarray(0, 8)
  const secretKey = keynumInfo.subarray(8, 72)
  const checksum = keynumInfo.subarray(72)
  const signatureAlgorithm = SKinfo.signatureAlgorithm

  var cksumData = Buffer.concat([Buffer.from(SKinfo.signatureAlgorithm), keyID, secretKey])
  sodium.crypto_generichash(ckSum, cksumData)

  assert(ckSum.equals(checksum))

  return {
    keyID,
    secretKey,
    checksum,
    signatureAlgorithm
  }
}

// takes arbitrary content buffer and returns signature buffer in minisgn format
function signContent (content, comment, SKdetails, trustComment, sigAlgorithm = 'Ed') {
  var contentToSign

  if (sigAlgorithm === 'ED') {
    var hashedContent = Buffer.alloc(sodium.crypto_generichash_BYTES_MAX)
    sodium.crypto_generichash(hashedContent, content)
    contentToSign = hashedContent
  } else {
    contentToSign = content
  }

  var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  var globalSignature = Buffer.alloc(sodium.crypto_sign_BYTES)

  sodium.crypto_sign_detached(signature, contentToSign, SKdetails.secretKey)

  var signatureInfo = Buffer.concat([Buffer.from(SKdetails.signatureAlgorithm), SKdetails.keyID, signature])
  var untrustedComment = ('untrusted comment: ' + comment)
  var trustedComment = ('trusted comment: ' + trustComment.toString('ascii'))

  var forGlobalSig = Buffer.concat([signature, Buffer.from(trustComment)])
  sodium.crypto_sign_detached(globalSignature, forGlobalSig, SKdetails.secretKey)

  var minisignStr = (untrustedComment + '\n' + signatureInfo.toString('base64') + '\n' + trustedComment + '\n' + globalSignature.toString('base64'))
  return Buffer.from(minisignStr)
}

// verify the signature of an arbitrary input
function verifySignature (signedContent, originalContent, publicKeyInfo) {
  var signature = parseSignature(signedContent)
//  console.log(signature.signature.equals(signature.globalSignature), 'a')
  if (!(signature.keyID.equals(publicKeyInfo.keyID))) {
    return ("error: keyID's do not match")
  } else {
    if (!(sodium.crypto_sign_verify_detached(signature.signature, originalContent, publicKeyInfo.publicKey))) {
      return ('error: signature verification failed')
    } else {
      var forGlobalSig = Buffer.concat([signature.signature, Buffer.from(signature.trustedComment)])
      if (!(sodium.crypto_sign_verify_detached(signature.globalSignature, forGlobalSig, publicKeyInfo.publicKey))) {
        console.log(signature.globalSignature.equals(signature.signature), signature.trustedComment.toString())
        return ('error: trusted comment cannot be verified')
      }
    }
  }
  return ('signature and comment successfully verified')
}

function keypairGen (comment, pwd, sigAlgorithm = 'Ed', kdfAlgorithm = 'Sc', cksumAlgorithm = 'B2') {
  var keyID = Buffer.alloc(8)
  var kdfSalt = Buffer.alloc(32)
  var kdfOutput = Buffer.alloc(104)

  var publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  var secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  var checkSum = Buffer.alloc(sodium.crypto_generichash_BYTES)

  var fullComment = Buffer.from('untrusted comment: ' + comment + '\n')

  const kdfOpsLimit = sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
  const kdfMemLimit = sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE

  sodium.randombytes_buf(keyID)
  sodium.randombytes_buf(kdfSalt)
  sodium.crypto_sign_keypair(publicKey, secretKey)

  var checksumData = Buffer.concat([Buffer.from(sigAlgorithm), keyID, secretKey])
  sodium.crypto_generichash(checkSum, checksumData)

  var keynumData = Buffer.concat([keyID, secretKey, checkSum])
  sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, Buffer.from(pwd), kdfSalt, kdfOpsLimit, kdfMemLimit)

  var keynumSK = xor(kdfOutput, keynumData)
  var algorithmInfo = Buffer.from(sigAlgorithm + kdfAlgorithm + cksumAlgorithm)
  var kdfLimits = Buffer.from(kdfOpsLimit.toString() + kdfMemLimit.toString())
  var SKinfo = Buffer.from(Buffer.concat([algorithmInfo, kdfSalt, kdfLimits, keynumSK]).toString('base64'))
  console.log(publicKey, 'a')

  return {
    publicKey,
    fullComment,
    SKinfo
  }
}

fs.readFile('test.txt', function (err, message) {
  if (err) throw err
  fs.readFile('test.txt.minisig', function (err, signature) {
    if (err) throw err
    fs.readFile('minisign.pub', function (err, publickey) {
      if (err) throw err
      var pubKey = parsePubkey(publickey)
      // console.log(verifySignature(signature, message, pubKey))
    })
  })
})

var newKeyInfo = keypairGen('hi', 'aa')
//console.log(newKeyInfo.SKinfoBase64)
console.log(extractSecretKey(Buffer.from('aa'), parseSecretKey(Buffer.concat([newKeyInfo.fullComment, newKeyInfo.SKinfo]))))

// load secret key file
//fs.readFile(secKeyFile, function (err, SKbuf) {
//  if (err) throw err
//  var SKinfo = parseSecretKey(SKbuf)
//  console.log(SKinfo)
//  var SKdetails = extractSecretKey(passwordBuf, SKinfo)
//})

//  // load content to be signed
//  fs.readFile(file, function (err, message) {
//    if (err) throw err
//    var toFile = signContent(message, '<insert comment here>', SKdetails, '<insert trusted comment here>')
//    console.log(toFile)

//    // write signature to file
//    fs.writeFile(signatureFile, toFile.toString(), function (err) {
//      if (err) throw err
//      console.log(`minsign signature saved to ${signatureFile}`)
//    })
//  })
//})
