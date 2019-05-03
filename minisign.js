// issues:
// ordering of keyID (minisign LE vs js BE)
// output- all buffers or strings for sigAlgorithm etc?
// what is signature algorithm in key files?
// make assertion errors more specific
// 'default' argument structure is wrong

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
var defaultComment = 'signature from minisign secret key'
var trustedComment = '<insert trusted comment here>'

const untrustedPrelude = Buffer.from('untrusted comment: ')
const trustedPrelude = Buffer.from('trusted comment: ')
const untrustedCommentStart = untrustedPrelude.byteLength
const expectedSignatureAlgorithm = Buffer.from('Ed')
const lineBreak = Buffer.from('\n')

// password for kdf algorithm - must correspond to the minisign public key
const passwordBuf = Buffer.from('')

function parsePubKey (pubkeyBuf) {
  assert(untrustedPrelude.equals(pubkeyBuf.subarray(0, untrustedCommentStart)))
  const untrustedCommentEnd = pubkeyBuf.indexOf('\n', untrustedCommentStart)
  const untrustedComment = pubkeyBuf.subarray(untrustedCommentStart, untrustedCommentEnd)

  const keyInfoStart = untrustedCommentStart + untrustedComment.byteLength + 1
  const keyInfoBase64 = pubkeyBuf.subarray(keyInfoStart, pubkeyBuf.indexOf('\n', keyInfoStart)).toString()
  const keyInfo = Buffer.from(keyInfoBase64, 'base64')

  const signatureAlgorithm = keyInfo.subarray(0, 2)
  const keyID = keyInfo.subarray(2, 10)
  const publicKey = keyInfo.subarray(10)
  assert(publicKey.byteLength === (sodium.crypto_sign_PUBLICKEYBYTES))

  return {
    untrustedComment,
    signatureAlgorithm,
    keyID,
    publicKey
  }
}

// totest: signatureBuf -> 
// takes signature buffer and returns info as buffers
function parseSignature (signatureBuf) {
  assert(untrustedPrelude.equals(signatureBuf.subarray(0, untrustedCommentStart)))

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

  assert(signatureBuf.subarray(sigInfoEnd + 1, trustedCommentStart).equals(trustedPrelude))
  assert(trustedCommentEnd === signatureBuf.length - 90)

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
  assert(untrustedPrelude.equals(secretKeyBuf.subarray(0, untrustedCommentStart)))

  const untrustedCommentEnd = secretKeyBuf.indexOf('\n', untrustedCommentStart)
  const untrustedComment = secretKeyBuf.subarray(untrustedCommentStart, untrustedCommentEnd).toString()

  const secretKeyInfoStart = untrustedCommentEnd + 1
  const secretKeyInfoEnd = secretKeyBuf.indexOf('\n', secretKeyInfoStart)
  const secretKeyInfoBase64 = secretKeyBuf.subarray(secretKeyInfoStart, secretKeyInfoEnd)
  const secretKeyInfo = Buffer.from(secretKeyInfoBase64.toString(), 'base64')

  assert(secretKeyInfoBase64.length = 212)

  const signatureAlgorithm = secretKeyInfo.subarray(0, 2).toString()
  const kdfAlgorithm = secretKeyInfo.subarray(2, 4).toString()
  const cksumAlgorithm = secretKeyInfo.subarray(4, 6).toString()
  const kdfSalt = secretKeyInfo.subarray(6, 38)
  const kdfOpsLimit = secretKeyInfo.readUInt32LE(38)
  const kdfMemLimit = secretKeyInfo.readUInt32LE(46)
  const keynumSK = secretKeyInfo.subarray(secretKeyInfo.length - 104)

  assert(keynumSK.slice(-1)[0], secretKeyBuf.slice(-2)[1])

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
function extractSecretKey (pwd, SKinfo) {
  var kdfOutput = Buffer.alloc(104)
  var keynumInfo
  var sumCheck = Buffer.alloc(sodium.crypto_generichash_BYTES)
  var opsLimit = SKinfo.kdfOpsLimit
  var memLimit = SKinfo.kdfMemLimit
  var salt = SKinfo.kdfSalt
  var password = Buffer.from(pwd)

  sodium.crypto_pwhash_scryptsalsa208sha256(kdfOutput, password, salt, opsLimit, memLimit)
  keynumInfo = xor(kdfOutput, SKinfo.keynumSK)
  const keyID = keynumInfo.subarray(0, 8)
  const secretKey = keynumInfo.subarray(8, 72)
  const checkSum = keynumInfo.subarray(72)
  const signatureAlgorithm = SKinfo.signatureAlgorithm
  const sigAlgoBuf = Buffer.from(SKinfo.signatureAlgorithm)

  var sumCheckData = Buffer.concat([sigAlgoBuf, keyID, secretKey])
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

// takes arbitrary content buffer and returns signature buffer in minisgn format
function signContent (content, SKdetails, comment = defaultComment, tComment = null, sigAlgorithm = 'Ed') {
  var contentToSign
  var signatureAlgorithm
  var trustComment

  if (sigAlgorithm === 'ED') {
    var hashedContent = Buffer.alloc(sodium.crypto_generichash_BYTES_MAX)
    sodium.crypto_generichash(hashedContent, content)
    contentToSign = hashedContent
    signatureAlgorithm = Buffer.from(sigAlgorithm)
  } else {
    contentToSign = content
    signatureAlgorithm = Buffer.from(SKdetails.signatureAlgorithm)
  }

  if (tComment == null) {
    trustComment = (Math.floor(Date.now() / 1000)).toString('10')
  } else {
    trustComment = tComment
  }

  var signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  var globalSignature = Buffer.alloc(sodium.crypto_sign_BYTES)

  sodium.crypto_sign_detached(signature, contentToSign, SKdetails.secretKey)

  var signatureInfo = Buffer.concat([signatureAlgorithm, SKdetails.keyID, signature])
  var untrustedComment = Buffer.from('untrusted comment: ' + comment + '\n')
  var trustedComment = Buffer.from('\ntrusted comment: ' + trustComment + '\n')
  var sigInfoBase64 = Buffer.from(signatureInfo.toString('base64'))

  var forGlobalSig = Buffer.concat([signature, Buffer.from(trustComment)])
  sodium.crypto_sign_detached(globalSignature, forGlobalSig, SKdetails.secretKey)
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

// verify the signature of an arbitrary input buffer
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
function keypairGen (pwd, comment = null, sigAlgorithm = 'Ed', kdfAlgorithm = 'Sc', cksumAlgorithm = 'B2') {
  var keyID = Buffer.alloc(8)
  var kdfSalt = Buffer.alloc(32)
  var kdfOutput = Buffer.alloc(104)

  var publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  var secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  var checkSum = Buffer.alloc(sodium.crypto_generichash_BYTES)

  sodium.randombytes_buf(keyID)
  sodium.randombytes_buf(kdfSalt)
  sodium.crypto_sign_keypair(publicKey, secretKey)

  if (comment === null) {
    comment = ('minisign public key ' + keyID.toString('hex').toUpperCase())
  }

  var fullComment = 'untrusted comment: ' + comment + '\n'

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

  var SKoutputBuffer = Buffer.from(fullComment + SKinfo)
  var PKoutputBuffer = Buffer.from(fullComment + PKinfo)

  return {
    publicKey,
    sigAlgorithm,
    keyID,
    SKinfo,
    PKoutputBuffer,
    SKoutputBuffer
  }
}

// fs.readFile('./test/fixtures/longComment.pub', function (err, data) {
//   if (err) throw err
//   var newKeys = keypairGen(data)
//   fs.writeFile('./test/fixtures/longPwd.pub', newKeys.PKoutputBuffer.toString(), function (err) {
//     if (err) throw err
//   })
//   fs.writeFile('./test/fixtures/longPwd.key', newKeys.SKoutputBuffer.toString(), function (err) {
//     if (err) throw err
//   })
// })

// fs.writeFile('./test/fixtures/keypairGen.key', newKeys.SKoutputBuffer.toString(), function (err) {
//   if (err) throw err
// })

// fs.readFile('./test/fixtures/noString.key', function (err, nostrkey) {
//   if (err) throw err
//   fs.readFile('./test/fixtures/test.key', function (err, testkey) {
//     if (err) throw err
//   })
// })

module.exports = {
  parsePubKey: parsePubKey,
  parseSignature: parseSignature,
  parseSecretKey: parseSecretKey,
  extractSecretKey: extractSecretKey,
  signContent: signContent,
  verifySignature: verifySignature,
  keypairGen: keypairGen
}

// testing input
//fs.readFile('test.txt', function (err, message) {
//  if (err) throw err
//  fs.readFile('test.txt.minisig', function (err, signature) {
//    if (err) throw err
//    fs.readFile('minisign.pub', function (err, publickey) {
//      if (err) throw err
//      var pubKey = parsePubKey(publickey)
//      // console.log(verifySignature(signature, message, pubKey))
//    })
//  })
//})

//var newKeyInfo = keypairGen('hi', 'aa')
////console.log(newKeyInfo.SKinfoBase64)
//var newSKInfo = parseSecretKey(Buffer.concat([newKeyInfo.fullComment, newKeyInfo.SKinfo]))
//var newSKdetails = extractSecretKey(Buffer.from('aa'), newSKInfo)
//var signMe = Buffer.from('hash me and sign me please.')

//var signedTest = signContent(signMe, 'testing', newSKdetails, 'trusted', 'ED')
//var newPublicKey = Buffer.concat([Buffer.from(newKeyInfo.sigAlgorithm), newKeyInfo.keyID, newKeyInfo.publicKey])
//console.log(newPublicKey.toString('base64'))
//fs.writeFile('toBeSigned.txt', signMe.toString(), function (err) {
//  if (err) throw err
//})
//fs.writeFile('test_sign1.txt', signedTest.toString(), function (err) {
//  if (err) throw err
//})
//console.log(verifySignature(signedTest, signMe, newKeyInfo))
//console.log(newKeyInfo.publicKey, reverse(Buffer.from('RWTFHh41viOjbhmRmNTBaqVkhZjJQxmzC/sVWgD7K31sqfapzWWldrjT', 'base64').subarray(2, 10)).toString('hex'))

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
