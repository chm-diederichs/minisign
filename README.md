# Minisign javaScript Tool

javaScript implementation of Frank Denis' (@jedisct1) [minisign tool](https://jedisct1.github.io/minisign/).

`minisignTool.js` contains functions for parsing minisign files (formatting is detailed in minisign documentation).

### Usage
```javascript
// load secret key
fs.readFile(secKeyFile, function (err, secretKeyBuffer) {
  if (err) throw err
  var SKinfo = parseSecretKey(secretKeyBuffer)
  SKinfo = extractSecretKey(passwordBuf, SKinfo.kdfSalt, SKinfo.kdfOpsLimit, SKinfo.kdfMemLimit, SKinfo.keynumSK)
  const secretKey = SK.secretKey
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

`extractSecretKey(pwd, kdfSalt, kdfOpsLimit, kdfMemLimit, keynumSK)` takes input password as `buffer` and encrypted key information from `parseSecretKey` and returns secret key information as a `dict` of `buffer`s:
```javascript
{
	keyID,
	secretKey,
	checksum
}