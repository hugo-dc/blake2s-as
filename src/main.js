//WebAssembly.instantiateStreaming(fetch("../build/optimized.wasm"), {
async function startup () {
  const response = await fetch("../build/optimized.wasm")
  const buffer = await response.arrayBuffer()
  const obj = await WebAssembly.instantiate(buffer)

  console.log(obj.instance.imports)
  var blake2sFunc = obj.instance.exports.blake2s

  var length = 32
  var key = new Uint8Array()
  var Blake2 = blake2sFunc(length, key)

  console.log(blake2sFunc)
  //console.log(Blake2)
}

startup()
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
