var path = require('path')
var fs = require('fs')
var minisign = require('./minisign')
const args = require('minimist')(process.argv.slice(2))
const cwd = process.cwd()

var sourceFile
var sigFile

var SKfile = path.join(process.env.HOME, 'minisign.key')
var PKfile = path.join(process.env.HOME, 'minisign.pub')

var tPrelude = 'trusted comment: '

function verify (signature, sourceFile, PKinfo, output, quiet) {
  fs.readFile(sourceFile, function (err, message) {
    if (err) throw err
    var sigInfo = minisign.parseSignature(signature)
    if (minisign.verifySignature(sigInfo, message, PKinfo)) {
      if (!quiet) {
        console.log('comment and signature verified.')
        console.log(tPrelude + sigInfo.trustedComment)
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

// generate keypair
if (args.G) {
  if (!args.k) {
    console.log('must provide a password')
    process.exit(1)
  }

  var newKeys = minisign.keypairGen(args.k)
  var keys = minisign.formatKeys(newKeys)

  if (args.p) {
    PKfile = path.resolve(cwd, args.p)
  }
  if (args.s) {
    SKfile = path.resolve(cwd, args.s)
  }

  fs.writeFile(PKfile, keys.PK.toString(), function (err) {
    if (err) throw err
  })
  fs.writeFile(SKfile, keys.SK.toString(), function (err) {
    if (err) throw err
  })
  console.log('public key save to ', PKfile)
  console.log('secret key encrypted and saved to ', SKfile)
}

// verifying a signature
if (args.V) {
  if (!args.m) {
    console.log('specify file to be verified')
    process.exit(1)
  }
  if (args.o && args.q) {
    console.log('cannot output content in quiet mode')
    process.exit(1)
  }
  if ((args.P  && args.p) || (!args.P && !args.p)) {
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
      verify(signature, sourceFile, PKinfo, args.o, args.q)
    } else {
      fs.readFile(PKfile, function (err, PK) {
        if (err) throw err
        var PKinfo = minisign.parsePubKey(PK)
        verify(signature, sourceFile, PKinfo, args.o, args.q)
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
