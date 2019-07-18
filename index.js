//var res = obj.__getArrayView(res)

const BLAKE2s = require('blake2s-js')
const assert = require('assert')
const fs = require("fs");
const loader = require('assemblyscript/lib/loader')

const digestLength = 32
const key = ''
var keyArr = decodeUTF8(key)
var length = 32


function ToInt32(x) {
    return x >>> 0;
}

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
  console.log('[JS] >>>>>')
  console.log(res)
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

  console.log('[WS] >>>>>')
  console.log(res)
  return res
}

function testDigestJS(value) {
  const h = new BLAKE2s(digestLength)
  h.update(decodeUTF8(value))
  var res = h.digest()
  //console.log('[JS] digest:\n', res)
  return res
}

function testDigestWasm(value) {
  var valueArr = decodeUTF8(value)
  const obj = loader.instantiateBuffer(fs.readFileSync(__dirname + "/build/optimized.wasm"))
  const id = obj.get_id()
  var msgRef = obj.__retain(obj.__allocArray(id, valueArr))
  var keyRef = obj.__retain(obj.__allocArray(id, keyArr))

  var res = obj.test_digest(length, keyRef, msgRef)
  var res = obj.__getArray(res)
  //console.log('[WS] digest:\n', res)
  return res
}

function testFinishedWasm(value) {
  
}

function testLoadedWasm(value) {
  var valueArr = decodeUTF8(value)
  const obj = loader.instantiateBuffer(fs.readFileSync(__dirname + "/build/optimized.wasm"))
  const id = obj.get_id()
  var keyRef = obj.__retain(obj.__allocArray(id, keyArr))

  res = obj.test_loaded(length, keyRef)
  //console.log('[WS] lodaded:  ', res)
  return res
}

function testNxJS(value) {
  const h = new BLAKE2s(digestLength)
  //h.update(decodeUTF8(value))
  //console.log('js-nx: ', h.nx)
  return h.nx
}

function testNxJS2(value) {
  const h = new BLAKE2s(digestLength)
  h.update(decodeUTF8(value))
  //console.log('(2)js-nx: ', h.nx)
  return h.nx
}

function testNxJS3(value) {
  const h = new BLAKE2s(digestLength)
  h.update(decodeUTF8(value))
  h.hexDigest()
  //console.log('(3)js-nx: ', h.nx)
  return h.nx
}

function testNx(value) {
  var valueArr = decodeUTF8(value)
  const obj = loader.instantiateBuffer(fs.readFileSync(__dirname + "/build/optimized.wasm"))
  const id = obj.get_id()
  var msgRef = obj.__retain(obj.__allocArray(id, valueArr))
  var keyRef = obj.__retain(obj.__allocArray(id, keyArr))

  res = obj.test_nx(length, keyRef, msgRef)

  //console.log('wasm-nx: ', res)
  return res
}

function testNx2(value) {
  var valueArr = decodeUTF8(value)
  const obj = loader.instantiateBuffer(fs.readFileSync(__dirname + "/build/optimized.wasm"))
  const id = obj.get_id()
  var msgRef = obj.__retain(obj.__allocArray(id, valueArr))
  var keyRef = obj.__retain(obj.__allocArray(id, keyArr))

  res = obj.test_nx2(length, keyRef, msgRef)
  //console.log('(2) wasm-nx: ', res)
  return res
}

function testNx3(value) {
  var valueArr = decodeUTF8(value)
  const obj = loader.instantiateBuffer(fs.readFileSync(__dirname + "/build/optimized.wasm"))
  const id = obj.get_id()
  var msgRef = obj.__retain(obj.__allocArray(id, valueArr))
  var keyRef = obj.__retain(obj.__allocArray(id, keyArr))

  res = obj.test_nx3(length, keyRef, msgRef)
  //console.log('(3) wasm-nx: ', res)
  return res
}

function testPreDigestH(value) {
  var valueArr = decodeUTF8(value)
  const obj = loader.instantiateBuffer(fs.readFileSync(__dirname + "/build/optimized.wasm"))
  const id = obj.get_id()
  var msgRef = obj.__retain(obj.__allocArray(id, valueArr))
  var keyRef = obj.__retain(obj.__allocArray(id, keyArr))

  res = obj.test_pre_digest_h(length, keyRef, msgRef)
  res = obj.__getArray(res)
  //console.log('[WS] pre_diggest this.h:\n', res)
  return res
}

function testPostDigestH(value) {
  var valueArr = decodeUTF8(value)
  const obj = loader.instantiateBuffer(fs.readFileSync(__dirname + "/build/optimized.wasm"))
  const id = obj.get_id()
  var msgRef = obj.__retain(obj.__allocArray(id, valueArr))
  var keyRef = obj.__retain(obj.__allocArray(id, keyArr))

  res = obj.test_post_digest_h(length, keyRef, msgRef)
  res = obj.__getArray(res)
  //console.log('[WS] post_digest this.h:\n', res)
  return res  
}

function testVWasm(value) {
    var valueArr = decodeUTF8(value)
  const obj = loader.instantiateBuffer(fs.readFileSync(__dirname + "/build/optimized.wasm"))
  const id = obj.get_id()
  var msgRef = obj.__retain(obj.__allocArray(id, valueArr))
  var keyRef = obj.__retain(obj.__allocArray(id, keyArr))

  res = obj.test_v(length, keyRef, msgRef)
  //res = obj.__getArray(res)
  console.log('[WS] v0: ', res)
  return res  
}

function testEmpty() {
  // test empty
  var val = 'hello world'
  var empty = ''
  //console.log('** EMPTY **')
  //assert.equal(testJS(empty), testWasm(empty))
  //console.log('** LOADED **')
  //testLoadedWasm(val)
  //console.log('** NX **')
  //assert.equal(testNxJS(val), testNx(val))
  //assert.equal(testNxJS2(val), testNx2(val))
  //assert.equal(testNxJS3(val), testNx3(val))
  assert.equal(testJS(val), testWasm(val))
  //console.log('** DIGEST **')
  //testDigestJS(val)
  //testDigestWasm(val)
  //console.log('** H **')
  //testPreDigestH(val)
  //testPostDigestH(val)
  //testVWasm(val)
}

testEmpty()


