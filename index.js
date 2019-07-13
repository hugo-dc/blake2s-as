const fs = require("fs");
const compiled = new WebAssembly.Module(fs.readFileSync(__dirname + "/build/optimized.wasm"));
const imports = {};
Object.defineProperty(module, "exports", {
  get: () => new WebAssembly.Instance(compiled, imports).exports
});

var instance = new WebAssembly.Instance(compiled)
var blake2s = instance.exports.blake2s
var key = new Uint8Array([])

var blakeObj = blake2s(32, key)

console.log(instance)
console.log(blake2s)
