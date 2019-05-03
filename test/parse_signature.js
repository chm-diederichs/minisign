var test = require('tape')
var minisign = require('../minisignTool')
var fs = require('fs')

test('key generation with comment', function (t) {
  var string = 'testing'
  var emojiString = 'testing👫'
  var noString = ''

  var stringCommentKey = minisign.keypairGen(string, string)
  var emojiCommentKey = minisign.keypairGen(emojiString, string)
  var noCommentKey = minisign.keypairGen(noString, string)

  fs.readFile('./fixtures/noString.key', function (err, SKinfo) {
    t.error(err)
    t.equal(stringCommentKey.SKinfo, SKinfo)
    t.end()
  })
})
