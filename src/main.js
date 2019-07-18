import { instantiateBuffer, ASUtil } from "../node_modules/assemblyscript/lib/loader"

function decodeUTF8(s) {
  var i, d = unescape(encodeURIComponent(s)), b = new Uint8Array(d.length);
  for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
  return b;
}

async function calculateDigest() {
  
  const response = await fetch("../build/optimized.wasm")
  const buffer = await response.arrayBuffer()
  const obj = await WebAssembly.instantiate(buffer)
  
  // Get message converting to Unix line breaks.
  var msg = document.getElementById('input').value.replace(/\r\n/g, '\n');
  var key = document.getElementById('key').value;
  var length = document.getElementById('digest-length').value;
  //try {
  //var h = new BLAKE2s(length, decodeUTF8(key));
  //} catch (e) {
  //  alert("Error: " + e);
  //}
  //h.update(decodeUTF8(msg));
  //document.getElementById('digest').innerHTML = h.hexDigest();


  console.log('imports: ', obj.instance.imports)
  console.log('exports: ', obj.instance.exports)
  var blake2sFunc = obj.instance.exports.blake2s
  console.log('blake2s: ', blake2sFunc)

  
  var res = blake2sFunc(length, decodeUTF8(key))
  var key = decodeUTF8(key)
  console.log('key: ', key)
  console.log('keyLength: ', key.length)
  console.log('result: ', res)

  console.log('Module: ', obj.module.__getString(res))
  //console.log(blake2sFunc)
}

/*
WebAssembly.instantiateStreaming(fetch("http://localhost:8000/build/optimized.wasm"), {
  env: {
    abort(_msg, _file, line, column) {
      console.error("abort called at main.ts:" + line + ":" + column);
    }
  },
}).then(result => {
  const exports = result.instance.exports;
  document.getElementById("container").textContent = "Result: " + exports.add(19, 23);
}).catch(console.error);
*/
