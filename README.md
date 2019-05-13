# `minisign`

[![Build Status](https://travis-ci.org/chm-diederichs/minisign.svg?branch=master)](https://travis-ci.org/chm-diederichs/minisign)

> JavaScript implementation of Frank Denis' (@jedisct1) [minisign tool](https://jedisct1.github.io/minisign/).

`minisign` is a CLI tool to perform minisign operations.

All functions are defined in `minisign.js`.

### Usage

## Generating a key pair

```
$ minisign -G
```

Public key is printed and saved to `minisign.pub` file in the current working directory by default; the secret key is encrypted and saved to `~/.minisign/minisign.key` by default.

```
$ minisign -G -p publicKey.pub -c 'comment appears in public key' -t 'comment will appear in secret key'
```

Flags may be used to designate specific file names and to introduce comments, which are displayed in the respective key files.

## Signing files

```
$ minisign -Sm example.txt
```

`example.txt` content is signed using `~/.minisign/minisign.key` and signature is saved to example.txt.minisig by default.

```
$ minisign -Sm example.txt -s specific.key -x signature.txt -t 'trusted comment'
```

Specific secret keys and signature files may be designated using the `-s` and `-x` flags respectively or the `-t` flag can be a trusted comment, which will be verified and displayed when verifying the file.

## Verifying a file

```
$ minisign -Vm example.txt -p example.pub
```

or

```
$ minisign -Vm example.txt -x signature.txt -P RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
```

If no signature file is specified, the signature file must be in the same directory as the original file and be of the form `(filename).minisig`. The public key may either be given as a file, `./minisign.pub` by default, or directly specified on the command line using the `-P` flag.

## Full usage information

```
 Usage:
 $ minisign -G [-F] [-p pubkey file] [-s seckey file] [-c pubkey comment] [-t seckey comment] -k pwd
 $ minisign -S [-H] [-s seckey file] [-x signature file] [-c comment] [-t trusted comment] -k pwd -m file
 $ minisign -V [-x signature file] [-p pubkey file | -P public key] [-o] [-q] -m file

 -G                generate a new key pair
 -S                sign a file
 -V                verify that a signature is valid for a given file
 -m <file>         file to sign/verify
 -o                combined with -V, output the file content after verification
 -H                combined with -S, pre-hash in order to sign large files
 -p <pubkeyfile>   public key file (default: ./minisign.pub)
 -P <pubkey>       public key, as a base64 string
 -s <seckey>       secret key file (default: ~/.minisign/minisign.key)
 -x <sigfile>      signature file (default: <file>.minisig)
 -c <comment>      add a one-line untrusted comment / comment for public key
 -t <comment>      add a one-line trusted comment / comment for secret key
 -q                quiet mode, suppress output
 -Q                pretty quiet mode, only print the trusted comment - overrides quiet mode
 -f                force. Combined with -G, overwrite a previous key pair
 -v                display version number
```

### API

## Public Key

`parsePubKey(pubKeyFileContent)` takes public key file content as a `buffer` and returns key information as`buffer`s:
```javascript
{
  untrustedComment,
  signatureAlgorithm,
  keyID,
  publicKey
}
```

`parseKeyCLI(pubKeyString)` takes a 56 character string and returns public key information as `buffers`:

```javascript
{
  signatureAlgorithm,
  keyID,
  publicKey
}
```

## Reading signature

`parseSignature(sigFileContent)` takes signature file content as a `buffer` and returns signature information as `buffer`s:

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

## Reading secret key

`parseSecretKey(secKeyFileContent)` takes secret key file content as a `buffer` and returns encrypted key information as `buffer`s if checksum is verified:

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

`extractSecretKey(pwd, secretKeyInfo)` takes input password as `buffer` and encrypted key information directly from `parseSecretKey` and returns secret key information as `buffer`s:

```javascript
{
  keyID,
  secretKey,
  sumCheck,
  checkSum,
  signatureAlgorithm
}
```

## Signing content provided as `buffer`

`signContent(content, SKdetails, opts)` takes content as `buffer`,  secret key details directly from `extractSecretKey` and `opts = { comment, tComment, sigAlgorithm = 'Ed' || 'ED' }` and returns a minisign formatted output together with signature properties:
```javascript
{
  outputBuf,
  untrustedComment,
  sigInfoBase64,
  trustComment,
  globalSigBase64
}
```

## Verifying signature

`verifySignature(signature, originalContent, publicKeyInfo)` first checks the key ID of the secret key used to sign corresponds to that of the public key given to verify, then the signature is verifieda nd lastly the global signature with the trusted comment included is verified. 

Returns `true` for succesful verification or prints `err` otherwise.

## Generating Keys

`keypairGen(passwordd, opts)` takes password as a secure buffer and `opts = { PKcomment, SKcomment, sigAlgorithm = 'Ed', kdfAlgorithm = 'Sc', ckSumAlgorithm = 'B2' }`. Returns key information as `buffer`s:

```javascript
{
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
```
`sigAlgorithm`, `kdfAlgorithm` and `ckSumAlgorithm` should be left as their default value as there is currently no support for alternative algorithms.

`formatKeys(keypairGenOutput)` takes the output of `keypairGen` directly and outputs minisign formatted key information as separate buffers:

```javascript
{
  PK,
  SK
}
```

## License

[ISC](LICENSE)
