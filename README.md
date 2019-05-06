# Minisign javaScript Tool

[![Build Status](https://travis-ci.org/chm-diederichs/minisign.svg?branch=master)](https://travis-ci.org/chm-diederichs/minisign)

javaScript implementation of Frank Denis' (@jedisct1) [minisign tool](https://jedisct1.github.io/minisign/).

`minisignTool.js` contains functions for parsing minisign files (formatting is detailed in minisign documentation).

### Usage
```javascript
// load secret key
fs.readFile(secKeyFile, function (err, secretKeyBuffer) {
  if (err) throw err
  var SKinfo = parseSecretKey(secretKeyBuffer)
  var SKdetails = extractSecretKey(passwordBuf, SKinfo)
  const secretKey = SKdetails.secretKey
})

// load public key
fs.readFile(pubKeyFile, function (err, publicKeyBuffer) {
  if (err) throw err
  var publicKeyInfo = parsePubKey(publicKeyInfo)
  const publicKey = publicKeyInfo.publicKey
})

// load and parse signature file
fs.readFile(signatureFile, function (err, signatureBuffer) {
  if (err) throw err
  var signatureInfo = parseSignature(signatureBuffer)
  const signature = signatureInfo.signature
})

// sign arbitrary content
var minsignOutput = signContent(content, 'untrusted comment', SKinfo, 'trusted comment')
```

### Reading public Key
`parsePubKey(pubKeyFileContent)` takes public key file content as a `buffer` and returns key information as a `dict` of `buffer`s:
```javascript
{
  untrustedComment,
  signatureAlgorithm,
  keyID,
  publicKey
}
```

### Reading signature
`parseSignature(sigFileContent)` takes signature file content as a `buffer` and returns signature information as a `dict` of `buffer`s:
```javascript
{
  untrustedComment,
  signatureAlgorithm,
  keyID,
  signature,
  trustedComment,
  globalSignature
}
```

### Reading secret key
`parseSecretKey(secKeyFileContent)` takes secret key file content as a `buffer` and returns encrypted key information as a `dict` of `buffer`s:
```javascript
{
  untrustedComment,
  signatureAlgorithm,
  kdfAlgorithm,
  cksumAlgorithm,
  kdfSalt,
  kdfOpsLimit,
  kdfMemLimit,
  keynumSK
}
```

`extractSecretKey(pwd, secretKeyInfo)` takes input password as `buffer` and encrypted key information directly from `parseSecretKey` and returns secret key information as a `dict` of `buffer`s:
```javascript
{
  keyID,
	secretKey,
	checksum
}
```

### Signing content provided as `buffer`
`signContent(content, comment, secretKeyDetails, trustComment)` takes content as `buffer` and both a comment (unsigned) and trusted comment (signed) as `string`s and secret key details directly from `extractSecretKey` and creates a `string` in minisign format and returns the `buffer` of this string.

### Verifying signature
