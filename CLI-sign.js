var path = require('path')
var fs = require('fs')
var minisign = require('./minisign')
const cwd = process.cwd()
const minimist = require('minimist')

var args = minimist(process.argv.slice(2), {
  string: ['m', 'x', 's', 'p', 'P', 'c', 't', 'k'],
  boolean: ['G', 'V', 'S', 'F', 'H', 'f', 'q', 'o', 'Q', 'help'],
  alias: { h: 'help' },
  unknown: function () {
    console.log('unrecognised command.')
    process.exit(1)
  }
})

const usage = `
  Usage:
  $ node CLI-sign -G [-F] [-p pubkey file] [-s seckey file] -k pwd
  $ node CLI-sign -S [-H] [-s seckey file] [-x signature file] [-c comment] [-t trusted comment] -k pwd -m file
  $ node ClI-sign -V [-x signature file] [-p pubkey file | -P public key] [-o] [-q] -m file

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
  -c <comment>      add a one-line untrusted comment
  -t <comment>      add a one-line trusted comment
  -q                quiet mode, suppress output
  -Q                pretty quiet mode, only print the trusted comment - overrides quiet mode
  -f                force. Combined with -G, overwrite a previous key pair
`

function verify (signature, sourceFile, PKinfo, output, quiet, pretty) {
  fs.readFile(sourceFile, function (err, message) {
    if (err) throw err
    var sigInfo = minisign.parseSignature(signature)
    if (minisign.verifySignature(sigInfo, message, PKinfo)) {
      if (!quiet && !pretty) {
        console.log('comment and signature verified.')
        console.log(tPrelude + sigInfo.trustedComment)
      } else if (pretty) {
        console.log(sigInfo.trustedComment.toString())
      }
      if (output) {
        console.log(message.toString())
      }
      process.exit()
    } else {
      if (!quiet) {
        console.log('signature verifaction failed.')
      }
      process.exit(1)
    }
  })
}

function sign (content, SKfile, sigFile, pwd, opts) {
  fs.readFile(SKfile, function (err, SK) {
    if (err) throw err
    var parsedSK = minisign.parseSecretKey(SK)
    var SKinfo = minisign.extractSecretKey(pwd, parsedSK)
    var signedOutput = minisign.signContent(content, SKinfo, opts)
    var toFile = signedOutput.outputBuf.toString()

    fs.writeFile(sigFile, toFile, function (err) {
      if (err) throw err
      console.log('signature saved to ', sigFile)
      process.exit()
    })
  })
}

if (args.help) {
  console.log(usage)
  process.exit(0)
}

// initiales fs variables
var sourceFile
var sigFile

var SKfile = path.join(process.env.HOME, 'minisign.key')
var PKfile = path.join(process.env.HOME, 'minisign.pub')

var tPrelude = 'trusted comment: '

// generate keypair
if (args.G) {
  if (!args.k) {
    console.log('must provide a password')
    process.exit(1)
  }

  var newKeys = minisign.keypairGen(args.k)
  var keys = minisign.formatKeys(newKeys)
  var overwrite = { flag: 'wx' }

  if (args.p) {
    PKfile = path.resolve(cwd, args.p)
  }
  if (args.s) {
    SKfile = path.resolve(cwd, args.s)
  }
  if (args.F) {
    overwrite.flag = 'w'
  }

  fs.writeFile(PKfile, keys.PK.toString(), overwrite, function (err) {
    if (err && err.code === 'EEXIST') {
      console.log('keys already exist, use -F tag to force overwrite')
      process.exit(1)
    }
    fs.writeFile(SKfile, keys.SK.toString(), overwrite, function (err) {
      if (err && err.code === 'EEXIST') {
        console.log('keys already exist, use -F tag to force overwrite')
        process.exit(1)
      }
    })
    console.log('public key save to ', PKfile)
    console.log('secret key encrypted and saved to ', SKfile)
  })
}

// verifying a signature
if (args.V) {
  if (!args.m) {
    console.log('specify file to be verified')
    process.exit(1)
  }
  if (args.o && (args.q || args.Q)) {
    console.log('cannot output content in quiet mode')
    process.exit(1)
  }
  if ((args.P && args.p) || (!args.P && !args.p)) {
    console.log('must provide unique key')
    process.exit(1)
  }

  sourceFile = path.normalize(args.m)
  sigFile = `${sourceFile}.minisig`

  if (args.p) {
    PKfile = path.resolve(cwd, args.p)
  }
  if (args.s) {
    SKfile = path.resolve(cwd, args.s)
  }
  if (args.x) {
    sigFile = path.resolve(cwd, args.x)
  }

  fs.readFile(sigFile, function (err, signature) {
    if (err) throw err
    if (args.P) {
      var PKinfo = minisign.parseKeyCLI(args.P)
      verify(signature, sourceFile, PKinfo, args.o, args.q, args.Q)
    } else {
      fs.readFile(PKfile, function (err, PK) {
        if (err) throw err
        var PKinfo = minisign.parsePubKey(PK)
        verify(signature, sourceFile, PKinfo, args.o, args.q, args.Q)
      })
    }
  })
}

// signing a file
if (args.S) {
  if (!args.m) {
    console.log('specify file to be verified')
    process.exit(1)
  }
  if (!args.k) {
    console.log('password required')
    process.exit(1)
  }

  sourceFile = path.normalize(args.m)
  sigFile = `${sourceFile}.minisig`

  var opts = {}
  opts.comment = args.c
  opts.tComment = args.t

  if (args.s) {
    SKfile = path.resolve(cwd, args.s)
  }
  if (args.x) {
    sigFile = path.resolve(cwd, args.x)
  }
  if (args.H) {
    opts.sigAlgorithm = 'ED'
  }

  fs.readFile(sourceFile, function (err, message) {
    if (err) throw err
    sign(message, SKfile, sigFile, args.k, opts)
  })
}
