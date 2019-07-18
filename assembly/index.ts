class Blake2s {
    MAX_DIGEST_LENGTH: i32 = 32
    BLOCK_LENGTH: i32 = 64
    MAX_KEY_LENGTH: i32 = 32
    PERSONALIZATION_LENGTH: i32 = 8
    SALT_LENGTH: i32 = 8
    IV: Uint32Array = new Uint32Array(8)
    isFinished: bool = false
    h: Uint32Array
    x: Uint8Array
    nx: i32
    t0: i32
    t1: i32
    f0: i32
    f1: i32
    result: Uint8Array = new Uint8Array(0)


    // testing
    param: Uint8Array
    loaded: i32
    partial: i32
    v0: u32
    v1: u32
    v2: u32
    v3: u32
    v4: u32
    v5: u32
    v6: u32
    v7: u32
    v8: u32
    v9: u32
    v10: u32
    v11: u32
    v12: u32
    v13: u32
    v14: u32
    v15: u32
    
    constructor(private digestLength: i32, keyOrConfig: Uint8Array, keyLength: i32) {
        this.result = new Uint8Array(digestLength)
        if (digestLength <= 0 || digestLength > this.MAX_DIGEST_LENGTH)
            throw new Error('bad digestLength')

        /*
        this.IV[0] = 0x6b08e667
        this.IV[1] = 0xbb67ae85
        this.IV[2] = 0x3c6ef372
        this.IV[3] = 0xa54ff53a
        this.IV[4] = 0x510e527f
        this.IV[5] = 0x9b05688c
        this.IV[6] = 0x1f83d9ab
        this.IV[7] = 0x5be0cd19
        */

        this.IV.fill(0x6a09e667, 0, 1)
        this.IV.fill(0xbb67ae85, 1, 2)
        this.IV.fill(0x3c6ef372, 2, 3)
        this.IV.fill(0xa54ff53a, 3, 4)
        this.IV.fill(0x510e527f, 4, 5)
        this.IV.fill(0x9b05688c, 5, 6)
        this.IV.fill(0x1f83d9ab, 6, 7)
        this.IV.fill(0x5be0cd19, 7, 8)

        var key = keyOrConfig

        this.isFinished = false
        //this.h = this.IV
        this.h = new Uint32Array(8)

        // TODO: Change this
        for (var j=0; j <this.IV.length; j++) {
            this.h[j] = this.IV[j]
        }
        var param = new Uint8Array(4)

        param[0] = digestLength & 0xff
        param[1] = keyLength
        param[2] = 1
        param[3] = 1

        this.param = param
        this.loaded = this.load32(param, 0)
        this.partial = (i32 (param[2] & 0xff)) << 16 // param[0] & 0xff | ((param[1] & 0xff) << 8) |
        

        this.h[0] = this.h[0] ^ this.load32(param, 0)

        // Buffer for data
        this.x = new Uint8Array(this.BLOCK_LENGTH)
        //this.x.fill(64, 0, 1)
        this.nx = 0

        // byte counter
        this.t0 = 0
        this.t1 = 0

        // flags
        this.f0 = 0
        this.f1 = 0

        // Fill buffer with key, if present
        if (keyLength > 0) {
            for (var i = 0; i < keyLength; i++)
                this.x[i] = key[i];
            for (i = keyLength; i < this.BLOCK_LENGTH; i++) this.x[i] = 0;
            this.nx = this.BLOCK_LENGTH;
        } 
    }

    load32(a: Uint8Array, i: i32): i32 {
        return (a[i + 0] & 0xff) | ((a[i + 1] & 0xff) << 8) |
            (i32 (a[i + 2] & 0xff) << 16) | (i32 (a[i + 3] & 0xff) << 24);
    }

    update(p: Uint8Array, offset: i32, length: i32): Blake2s {
        if (this.isFinished)
            throw new Error('update() after calling digest()');

        if (length == 0) return this

        var left = 64 - this.nx // 53
        var i = 0

        // Finish buffer.
        if (length > left) {
            for (i = 0; i < left; i++) {
                this.x[this.nx + i] = p[offset + i];
            }
            this.processBlock(64);
            offset += left;
            length -= left;
            this.nx = 0;
        }

        // Process message blocks.
        while (length > 64) {
            for (i = 0; i < 64; i++) {
                this.x[i] = p[offset + i];
            }
            this.processBlock(64);
            offset += 64;
            length -= 64;
            this.nx = 0;
        }

        // Copy leftovers to buffer.
        for (i = 0; i < length; i++) {
            this.x[this.nx + i] = p[offset + i];
        }

        this.nx += length;
        return this;

    }

    processBlock(length: i32): void {
        this.t0 += length;
        if (this.t0 != this.t0 >>> 0) {
            this.t0 = 0;
            this.t1++;
        }

        this.v0  = this.h[0]
        this.v1  = this.h[1]
        this.v2  = this.h[2]
        this.v3  = this.h[3]
        this.v4  = this.h[4]
        this.v5  = this.h[5]
        this.v6  = this.h[6]
        this.v7  = this.h[7]
        this.v8  = this.IV[0]
        this.v9  = this.IV[1]
        this.v10 = this.IV[2]
        this.v11 = this.IV[3]
        this.v12 = this.IV[4] ^ this.t0
        this.v13 = this.IV[5] ^ this.t1
        this.v14 = this.IV[6] ^ this.f0
        this.v15 = this.IV[7] ^ this.f1

        var x = this.x;
        var m0  = i32(x[ 0]) & 0xff | (i32(x[ 1]) & 0xff) << 8 | (i32(x[ 2]) & 0xff) << 16 | (i32(x[ 3]) & 0xff) << 24
        var m1  = i32(x[ 4]) & 0xff | (i32(x[ 5]) & 0xff) << 8 | (i32(x[ 6]) & 0xff) << 16 | (i32(x[ 7]) & 0xff) << 24
        var m2  = i32(x[ 8]) & 0xff | (i32(x[ 9]) & 0xff) << 8 | (i32(x[10]) & 0xff) << 16 | (i32(x[11]) & 0xff) << 24
        var m3  = i32(x[12]) & 0xff | (i32(x[13]) & 0xff) << 8 | (i32(x[14]) & 0xff) << 16 | (i32(x[15]) & 0xff) << 24
        var m4  = i32(x[16]) & 0xff | (i32(x[17]) & 0xff) << 8 | (i32(x[18]) & 0xff) << 16 | (i32(x[19]) & 0xff) << 24
        var m5  = i32(x[20]) & 0xff | (i32(x[21]) & 0xff) << 8 | (i32(x[22]) & 0xff) << 16 | (i32(x[23]) & 0xff) << 24
        var m6  = i32(x[24]) & 0xff | (i32(x[25]) & 0xff) << 8 | (i32(x[26]) & 0xff) << 16 | (i32(x[27]) & 0xff) << 24
        var m7  = i32(x[28]) & 0xff | (i32(x[29]) & 0xff) << 8 | (i32(x[30]) & 0xff) << 16 | (i32(x[31]) & 0xff) << 24
        var m8  = i32(x[32]) & 0xff | (i32(x[33]) & 0xff) << 8 | (i32(x[34]) & 0xff) << 16 | (i32(x[35]) & 0xff) << 24
        var m9  = i32(x[36]) & 0xff | (i32(x[37]) & 0xff) << 8 | (i32(x[38]) & 0xff) << 16 | (i32(x[39]) & 0xff) << 24
        var m10 = i32(x[40]) & 0xff | (i32(x[41]) & 0xff) << 8 | (i32(x[42]) & 0xff) << 16 | (i32(x[43]) & 0xff) << 24
        var m11 = i32(x[44]) & 0xff | (i32(x[45]) & 0xff) << 8 | (i32(x[46]) & 0xff) << 16 | (i32(x[47]) & 0xff) << 24
        var m12 = i32(x[48]) & 0xff | (i32(x[49]) & 0xff) << 8 | (i32(x[50]) & 0xff) << 16 | (i32(x[51]) & 0xff) << 24
        var m13 = i32(x[52]) & 0xff | (i32(x[53]) & 0xff) << 8 | (i32(x[54]) & 0xff) << 16 | (i32(x[55]) & 0xff) << 24
        var m14 = i32(x[56]) & 0xff | (i32(x[57]) & 0xff) << 8 | (i32(x[58]) & 0xff) << 16 | (i32(x[59]) & 0xff) << 24
        var m15 = i32(x[60]) & 0xff | (i32(x[61]) & 0xff) << 8 | (i32(x[62]) & 0xff) << 16 | (i32(x[63]) & 0xff) << 24

        // Round 1.
        //this.v0 = m0

        this.v0 = this.v0 + m0 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v1 = this.v1 + m2 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v2 = this.v2 + m4 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v3 = this.v3 + m6 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v2 = this.v2 + m5 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v3 = this.v3 + m7 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v1 = this.v1 + m3 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;
        this.v0 = this.v0 + m1 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v0 = this.v0 + m8 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v1 = this.v1 + m10 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v2 = this.v2 + m12 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v3 = this.v3 + m14 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v2 = this.v2 + m13 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v3 = this.v3 + m15 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v1 = this.v1 + m11 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v0 = this.v0 + m9 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;

        // Round 2.
        this.v0 = this.v0 + m14 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v1 = this.v1 + m4 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v2 = this.v2 + m9 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v3 = this.v3 + m13 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v2 = this.v2 + m15 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v3 = this.v3 + m6 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v1 = this.v1 + m8 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;
        this.v0 = this.v0 + m10 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v0 = this.v0 + m1 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v1 = this.v1 + m0 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v2 = this.v2 + m11 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v3 = this.v3 + m5 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v2 = this.v2 + m7 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v3 = this.v3 + m3 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v1 = this.v1 + m2 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v0 = this.v0 + m12 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;

        // Round 3.
        this.v0 = this.v0 + m11 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v1 = this.v1 + m12 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v2 = this.v2 + m5 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v3 = this.v3 + m15 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v2 = this.v2 + m2 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v3 = this.v3 + m13 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v1 = this.v1 + m0 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;
        this.v0 = this.v0 + m8 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v0 = this.v0 + m10 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v1 = this.v1 + m3 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v2 = this.v2 + m7 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v3 = this.v3 + m9 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v2 = this.v2 + m1 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v3 = this.v3 + m4 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v1 = this.v1 + m6 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v0 = this.v0 + m14 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;

        // Round 4.
        this.v0 = this.v0 + m7 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v1 = this.v1 + m3 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v2 = this.v2 + m13 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v3 = this.v3 + m11 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v2 = this.v2 + m12 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v3 = this.v3 + m14 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v1 = this.v1 + m1 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;
        this.v0 = this.v0 + m9 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v0 = this.v0 + m2 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v1 = this.v1 + m5 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v2 = this.v2 + m4 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v3 = this.v3 + m15 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v2 = this.v2 + m0 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v3 = this.v3 + m8 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v1 = this.v1 + m10 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v0 = this.v0 + m6 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;

        // Round 5.
        this.v0 = this.v0 + m9 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v1 = this.v1 + m5 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v2 = this.v2 + m2 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v3 = this.v3 + m10 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v2 = this.v2 + m4 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v3 = this.v3 + m15 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v1 = this.v1 + m7 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;
        this.v0 = this.v0 + m0 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v0 = this.v0 + m14 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v1 = this.v1 + m11 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v2 = this.v2 + m6 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v3 = this.v3 + m3 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v2 = this.v2 + m8 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v3 = this.v3 + m13 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v1 = this.v1 + m12 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v0 = this.v0 + m1 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;

        // Round 6.
        this.v0 = this.v0 + m2 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v1 = this.v1 + m6 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v2 = this.v2 + m0 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v3 = this.v3 + m8 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v2 = this.v2 + m11 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v3 = this.v3 + m3 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v1 = this.v1 + m10 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;
        this.v0 = this.v0 + m12 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v0 = this.v0 + m4 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v1 = this.v1 + m7 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v2 = this.v2 + m15 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v3 = this.v3 + m1 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v2 = this.v2 + m14 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v3 = this.v3 + m9 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v1 = this.v1 + m5 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v0 = this.v0 + m13 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;

        // Round 7.
        this.v0 = this.v0 + m12 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v1 = this.v1 + m1 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v2 = this.v2 + m14 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v3 = this.v3 + m4 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v2 = this.v2 + m13 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v3 = this.v3 + m10 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v1 = this.v1 + m15 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;
        this.v0 = this.v0 + m5 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v0 = this.v0 + m0 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v1 = this.v1 + m6 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v2 = this.v2 + m9 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v3 = this.v3 + m8 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v2 = this.v2 + m2 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v3 = this.v3 + m11 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v1 = this.v1 + m3 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v0 = this.v0 + m7 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;

        // Round 8.
        this.v0 = this.v0 + m13 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v1 = this.v1 + m7 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v2 = this.v2 + m12 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v3 = this.v3 + m3 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v2 = this.v2 + m1 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v3 = this.v3 + m9 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v1 = this.v1 + m14 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;
        this.v0 = this.v0 + m11 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v0 = this.v0 + m5 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v1 = this.v1 + m15 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v2 = this.v2 + m8 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v3 = this.v3 + m2 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v2 = this.v2 + m6 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v3 = this.v3 + m10 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v1 = this.v1 + m4 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v0 = this.v0 + m0 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;

        // Round 9.
        this.v0 = this.v0 + m6 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v1 = this.v1 + m14 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v2 = this.v2 + m11 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v3 = this.v3 + m0 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v2 = this.v2 + m3 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v3 = this.v3 + m8 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v1 = this.v1 + m9 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;
        this.v0 = this.v0 + m15 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v0 = this.v0 + m12 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v1 = this.v1 + m13 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v2 = this.v2 + m1 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v3 = this.v3 + m10 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v2 = this.v2 + m4 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v3 = this.v3 + m5 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v1 = this.v1 + m7 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v0 = this.v0 + m2 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;

        // Round 10.
        this.v0 = this.v0 + m10 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v1 = this.v1 + m8 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v2 = this.v2 + m7 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v3 = this.v3 + m1 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v2 = this.v2 + m6 | 0;
        this.v2 = this.v2 + this.v6 | 0;
        this.v14 ^= this.v2;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v10 = this.v10 + this.v14 | 0;
        this.v6 ^= this.v10;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v3 = this.v3 + m5 | 0;
        this.v3 = this.v3 + this.v7 | 0;
        this.v15 ^= this.v3;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v11 = this.v11 + this.v15 | 0;
        this.v7 ^= this.v11;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v1 = this.v1 + m4 | 0;
        this.v1 = this.v1 + this.v5 | 0;
        this.v13 ^= this.v1;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v9 = this.v9 + this.v13 | 0;
        this.v5 ^= this.v9;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;
        this.v0 = this.v0 + m2 | 0;
        this.v0 = this.v0 + this.v4 | 0;
        this.v12 ^= this.v0;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v8 = this.v8 + this.v12 | 0;
        this.v4 ^= this.v8;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v0 = this.v0 + m15 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 16) | this.v15 >>> 16;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 12) | this.v5 >>> 12;
        this.v1 = this.v1 + m9 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 16) | this.v12 >>> 16;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 12) | this.v6 >>> 12;
        this.v2 = this.v2 + m3 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 16) | this.v13 >>> 16;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 12) | this.v7 >>> 12;
        this.v3 = this.v3 + m13 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 16) | this.v14 >>> 16;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 12) | this.v4 >>> 12;
        this.v2 = this.v2 + m12 | 0;
        this.v2 = this.v2 + this.v7 | 0;
        this.v13 ^= this.v2;
        this.v13 = this.v13 << (32 - 8) | this.v13 >>> 8;
        this.v8 = this.v8 + this.v13 | 0;
        this.v7 ^= this.v8;
        this.v7 = this.v7 << (32 - 7) | this.v7 >>> 7;
        this.v3 = this.v3 + m0 | 0;
        this.v3 = this.v3 + this.v4 | 0;
        this.v14 ^= this.v3;
        this.v14 = this.v14 << (32 - 8) | this.v14 >>> 8;
        this.v9 = this.v9 + this.v14 | 0;
        this.v4 ^= this.v9;
        this.v4 = this.v4 << (32 - 7) | this.v4 >>> 7;
        this.v1 = this.v1 + m14 | 0;
        this.v1 = this.v1 + this.v6 | 0;
        this.v12 ^= this.v1;
        this.v12 = this.v12 << (32 - 8) | this.v12 >>> 8;
        this.v11 = this.v11 + this.v12 | 0;
        this.v6 ^= this.v11;
        this.v6 = this.v6 << (32 - 7) | this.v6 >>> 7;
        this.v0 = this.v0 + m11 | 0;
        this.v0 = this.v0 + this.v5 | 0;
        this.v15 ^= this.v0;
        this.v15 = this.v15 << (32 - 8) | this.v15 >>> 8;
        this.v10 = this.v10 + this.v15 | 0;
        this.v5 ^= this.v10;
        this.v5 = this.v5 << (32 - 7) | this.v5 >>> 7;
        
        this.h[0] ^= this.v0 ^ this.v8;
        this.h[1] ^= this.v1 ^ this.v9;
        this.h[2] ^= this.v2 ^ this.v10;
        this.h[3] ^= this.v3 ^ this.v11;
        this.h[4] ^= this.v4 ^ this.v12;
        this.h[5] ^= this.v5 ^ this.v13;
        this.h[6] ^= this.v6 ^ this.v14;
        this.h[7] ^= this.v7 ^ this.v15;
    }

    digest (): Uint8Array {
        if (this.isFinished) return this.result;

        for (var i = this.nx; i < 64; i++){
            this.x[i] = 0;
        }

        // Set last block flag.
        this.f0 = 0xffffffff;

        //TODO in tree mode, set f1 to 0xffffffff.
        this.processBlock(this.nx);

        var d = new Uint8Array(32);

        for (i = 0; i < 8; i++) {
            var h = this.h[i];
            d[i * 4 + 0] = (h >>> 0) & 0xff;
            d[i * 4 + 1] = (h >>> 8) & 0xff;
            d[i * 4 + 2] = (h >>> 16) & 0xff;
            d[i * 4 + 3] = (h >>> 24) & 0xff;
        }

        this.result = new Uint8Array(this.digestLength)
        this.result = d.subarray(0, this.digestLength);
        this.isFinished = true;

        return this.result;        

    }


    hexDigest(): string {
        var hex: Array<string> = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
        var out: Array<string> = []
        var d = this.digest();
        for (var i = 0; i < d.length; i++) {
            out.push(hex[(d[i] >> 4) & 0xf]);
            out.push(hex[d[i] & 0xf]);
        }
        return out.join('');        
    }

    example(): i32 {
        return 42
    }
}

export function blake2s(digestLength: i32, keyOrConfig: Uint8Array, msg: Uint8Array): string {
    var blake2s = new Blake2s(digestLength, keyOrConfig, keyOrConfig.length)

    blake2s.update(msg, 0, msg.length) // check updated

    var res = blake2s.digest() // check digest
    return blake2s.hexDigest()

}

export function test_loaded(digestLength: i32, keyOrConfig: Uint8Array): i32 {
    var blake2s = new Blake2s(digestLength, keyOrConfig, keyOrConfig.length)
    //blake2s.update(msg, 0, msg.length)
    return blake2s.loaded
}

export function test_nx(digestLength: i32, keyOrConfig: Uint8Array, msg: Uint8Array): i32 {
    var blake2s = new Blake2s(digestLength, keyOrConfig, keyOrConfig.length)
    return blake2s.nx
}

export function test_nx2(digestLength: i32, keyOrConfig: Uint8Array, msg: Uint8Array): i32 {
    var blake2s = new Blake2s(digestLength, keyOrConfig, keyOrConfig.length)
    blake2s.update(msg, 0, msg.length)
    return blake2s.nx
}

export function test_nx3(digestLength: i32, keyOrConfig: Uint8Array, msg: Uint8Array): i32 {
    var blake2s = new Blake2s(digestLength, keyOrConfig, keyOrConfig.length)
    blake2s.update(msg, 0, msg.length)
    var res = blake2s.hexDigest()
    return blake2s.nx
}

export function test_digest(digestLength: i32, keyOrConfig: Uint8Array, msg: Uint8Array): Uint8Array {
    var blake2s = new Blake2s(digestLength, keyOrConfig, keyOrConfig.length)
    blake2s.update(msg, 0, msg.length)
    return blake2s.digest()
}

export function test_pre_digest_h (digestLength: i32, keyOrConfig: Uint8Array, msg: Uint8Array): Uint32Array {
    var blake2s = new Blake2s(digestLength, keyOrConfig, keyOrConfig.length)
    blake2s.update(msg, 0, msg.length)
    return blake2s.h
}

export function test_post_digest_h (digestLength: i32, keyOrConfig: Uint8Array, msg: Uint8Array): Uint32Array {
    var blake2s = new Blake2s(digestLength, keyOrConfig, keyOrConfig.length)
    blake2s.update(msg, 0, msg.length)
    var dig = blake2s.digest()
    return blake2s.h
}

export function test_v(digestLength: i32, keyOrConfig: Uint8Array, msg: Uint8Array): u32 {
    var blake2s = new Blake2s(digestLength, keyOrConfig, keyOrConfig.length)
    blake2s.update(msg, 0, msg.length)
    var dig = blake2s.digest()
    return blake2s.v0
}


export function test_finished(digestLength: i32, keyOrConfig: Uint8Array, msg: Uint8Array): bool {
    var blake2s = new Blake2s(digestLength, keyOrConfig, keyOrConfig.length)
    blake2s.update(msg, 0, msg.length)
    return blake2s.isFinished
}

export function get_id (): i32 {
    return idof<Uint8Array>()
}
