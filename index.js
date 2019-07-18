const BLAKE2s = require('blake2s-js')
const assert = require('assert')
const fs = require("fs");
const loader = require('assemblyscript/lib/loader')

const digestLength = 32
const key = ''
var keyArr = decodeUTF8(key)
var length = 32


function decodeUTF8(s) {
  var i, d = unescape(encodeURIComponent(s))
  var b = new Uint8Array(d.length);
  for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
  return b;
}

function testJS(value) {
  const h = new BLAKE2s(digestLength)
  h.update(decodeUTF8(value))
  var res = h.hexDigest()
  return res
}

function testWasm(value) {
  var valueArr = decodeUTF8(value)
  const obj = loader.instantiateBuffer(fs.readFileSync(__dirname + "/build/optimized.wasm"))
  const id = obj.get_id()
  var msgRef = obj.__retain(obj.__allocArray(id, valueArr))
  var keyRef = obj.__retain(obj.__allocArray(id, keyArr))

  var res = obj.blake2s(length, keyRef, msgRef)
  var res = obj.__getString(res)

  return res
}


function testBlake2s() {
  var val = 'hello world'
  var empty = ''

  assert.equal(testJS(val), testWasm(val))
}

testBlake2s()


