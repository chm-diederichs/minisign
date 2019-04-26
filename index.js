const fs = require('fs')
const assert = require('assert')

const file = 'example.txt'
const publicKeyFile = 'minisign.pub'

const signatureFile = 'example.txt.minisig'

function verify (pubkeyBuf, fileBuf, sigBuf) {

}

const pubkeyPrelude = Buffer.from('untrusted comment: ')
const expectedSignatureAlgorithm = Buffer.from('Ed')
function parsePubkey (pubkeyBuf) {
  const trustedCommentStart = pubkeyPrelude.byteLength
  assert(pubkeyPrelude.equals(pubkeyBuf.subarray(0, trustedCommentStart)))
  const trustedComment = pubkeyBuf.subarray(trustedCommentStart, pubkeyBuf.indexOf('\n', trustedCommentStart))

  const keyInfoStart = trustedCommentStart + trustedComment.byteLength + 1
  const keyInfoBase64 = pubkeyBuf.subarray(keyInfoStart, pubkeyBuf.indexOf('\n', keyInfoStart)).toString()
  const keyInfo = Buffer.from(keyInfoBase64, 'base64')

  const signatureAlgorithm = keyInfo.subarray(0, 2)
  const keyId = keyInfo.subarray(2, 10)
  const publicKey = keyInfo.subarray(10)

  assert(signatureAlgorithm.equals(expectedSignatureAlgorithm))

  return {
    trustedComment,
    signatureAlgorithm,
    keyId,
    publicKey
  }
}

fs.readFile(publicKeyFile, function (err, pubkeyBuf) {
  if (err) throw err

  console.log(parsePubkey(pubkeyBuf))
})
