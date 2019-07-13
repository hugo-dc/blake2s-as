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
    result: Uint8Array
    
    constructor (private digestLength: i32, keyOrConfig: Uint8Array) {
        this.IV.fill(0x6a09e667, 0, 4)
        this.IV.fill(0xbb67ae85, 4, 8)
        this.IV.fill(0x3c6ef372, 8, 12)
        this.IV.fill(0xa54ff53a, 12, 16)
        this.IV.fill(0x510e527f, 16, 20)
        this.IV.fill(0x9b05688c, 20, 24)
        this.IV.fill(0x1f83d9ab, 24, 28)
        this.IV.fill(0x5be0cd19, 28, 32)

        //if (digestLength <= 0 || digestLength > this.MAX_DIGEST_LENGTH)
            //throw new Error('bad digestLength');

        
        var key = keyOrConfig
        var keyLength = key.length

        //if (keyLength > this.MAX_KEY_LENGTH)
        //    throw new Error('key is too long');

        this.isFinished = false
        this.h = this.IV
        var param = new Uint8Array(4)

        param.fill(digestLength & 0xff, 0, 1)
        param.fill(keyLength, 1, 2)
        param.fill(1, 2, 3)
        param.fill(1, 3, 4)
        
        this.h[0] = this.h[0] ^ this.load32(param, 0)

        // Buffer for data
        this.x = new Uint8Array(1)
        this.x.fill(64, 0, 1)
        this.nx = 0

        // byte counter
        this.t0 = 0
        this.t1 = 0

        // flags
        this.f0 = 0
        this.f1 = 0

        // Fill buffer with key, if present
        if (keyLength > 0) {
            for (var i = 0; i < keyLength; i++) this.x[i] = key[i];
            for (i = keyLength; i < this.BLOCK_LENGTH; i++) this.x[i] = 0;
            this.nx = this.BLOCK_LENGTH;
        }        
    }

    load32(a: Uint8Array, i: i32): i32 {
        return (a[i + 0] & 0xff) | ((a[i + 1] & 0xff) << 8) |
            ((a[i + 2] & 0xff) << 16) | ((a[i + 3] & 0xff) << 24);
    }

    processBlock(length: i32): void {
        this.t0 += length;
        if (this.t0 != this.t0 >>> 0) {
            this.t0 = 0;
            this.t1++;
        }

        var v0  = this.h[0],
        v1  = this.h[1],
        v2  = this.h[2],
        v3  = this.h[3],
        v4  = this.h[4],
        v5  = this.h[5],
        v6  = this.h[6],
        v7  = this.h[7],
        v8  = this.IV[0],
        v9  = this.IV[1],
        v10 = this.IV[2],
        v11 = this.IV[3],
        v12 = this.IV[4] ^ this.t0,
        v13 = this.IV[5] ^ this.t1,
        v14 = this.IV[6] ^ this.f0,
        v15 = this.IV[7] ^ this.f1;

        var x = this.x;
        var m0  = x[ 0] & 0xff | (x[ 1] & 0xff) << 8 | (x[ 2] & 0xff) << 16 | (x[ 3] & 0xff) << 24,
        m1  = x[ 4] & 0xff | (x[ 5] & 0xff) << 8 | (x[ 6] & 0xff) << 16 | (x[ 7] & 0xff) << 24,
        m2  = x[ 8] & 0xff | (x[ 9] & 0xff) << 8 | (x[10] & 0xff) << 16 | (x[11] & 0xff) << 24,
        m3  = x[12] & 0xff | (x[13] & 0xff) << 8 | (x[14] & 0xff) << 16 | (x[15] & 0xff) << 24,
        m4  = x[16] & 0xff | (x[17] & 0xff) << 8 | (x[18] & 0xff) << 16 | (x[19] & 0xff) << 24,
        m5  = x[20] & 0xff | (x[21] & 0xff) << 8 | (x[22] & 0xff) << 16 | (x[23] & 0xff) << 24,
        m6  = x[24] & 0xff | (x[25] & 0xff) << 8 | (x[26] & 0xff) << 16 | (x[27] & 0xff) << 24,
        m7  = x[28] & 0xff | (x[29] & 0xff) << 8 | (x[30] & 0xff) << 16 | (x[31] & 0xff) << 24,
        m8  = x[32] & 0xff | (x[33] & 0xff) << 8 | (x[34] & 0xff) << 16 | (x[35] & 0xff) << 24,
        m9  = x[36] & 0xff | (x[37] & 0xff) << 8 | (x[38] & 0xff) << 16 | (x[39] & 0xff) << 24,
        m10 = x[40] & 0xff | (x[41] & 0xff) << 8 | (x[42] & 0xff) << 16 | (x[43] & 0xff) << 24,
        m11 = x[44] & 0xff | (x[45] & 0xff) << 8 | (x[46] & 0xff) << 16 | (x[47] & 0xff) << 24,
        m12 = x[48] & 0xff | (x[49] & 0xff) << 8 | (x[50] & 0xff) << 16 | (x[51] & 0xff) << 24,
        m13 = x[52] & 0xff | (x[53] & 0xff) << 8 | (x[54] & 0xff) << 16 | (x[55] & 0xff) << 24,
        m14 = x[56] & 0xff | (x[57] & 0xff) << 8 | (x[58] & 0xff) << 16 | (x[59] & 0xff) << 24,
        m15 = x[60] & 0xff | (x[61] & 0xff) << 8 | (x[62] & 0xff) << 16 | (x[63] & 0xff) << 24;

        // Round 1.
        v0 = v0 + m0 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m2 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m4 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m6 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m5 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m7 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m3 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m1 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m8 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m10 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m12 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m14 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m13 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m15 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m11 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m9 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 2.
        v0 = v0 + m14 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m4 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m9 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m13 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m15 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m6 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m8 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m10 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m1 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m0 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m11 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m5 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m7 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m3 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m2 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m12 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 3.
        v0 = v0 + m11 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m12 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m5 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m15 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m2 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m13 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m0 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m8 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m10 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m3 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m7 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m9 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m1 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m4 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m6 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m14 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 4.
        v0 = v0 + m7 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m3 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m13 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m11 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m12 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m14 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m1 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m9 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m2 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m5 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m4 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m15 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m0 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m8 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m10 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m6 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 5.
        v0 = v0 + m9 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m5 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m2 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m10 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m4 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m15 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m7 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m0 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m14 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m11 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m6 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m3 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m8 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m13 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m12 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m1 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 6.
        v0 = v0 + m2 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m6 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m0 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m8 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m11 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m3 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m10 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m12 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m4 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m7 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m15 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m1 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m14 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m9 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m5 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m13 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 7.
        v0 = v0 + m12 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m1 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m14 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m4 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m13 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m10 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m15 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m5 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m0 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m6 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m9 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m8 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m2 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m11 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m3 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m7 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 8.
        v0 = v0 + m13 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m7 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m12 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m3 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m1 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m9 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m14 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m11 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m5 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m15 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m8 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m2 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m6 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m10 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m4 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m0 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 9.
        v0 = v0 + m6 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m14 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m11 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m0 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m3 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m8 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m9 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m15 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m12 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m13 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m1 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m10 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m4 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m5 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m7 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m2 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        // Round 10.
        v0 = v0 + m10 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v1 = v1 + m8 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v2 = v2 + m7 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v3 = v3 + m1 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v2 = v2 + m6 | 0;
        v2 = v2 + v6 | 0;
        v14 ^= v2;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v10 = v10 + v14 | 0;
        v6 ^= v10;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v3 = v3 + m5 | 0;
        v3 = v3 + v7 | 0;
        v15 ^= v3;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v11 = v11 + v15 | 0;
        v7 ^= v11;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v1 = v1 + m4 | 0;
        v1 = v1 + v5 | 0;
        v13 ^= v1;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v9 = v9 + v13 | 0;
        v5 ^= v9;
        v5 = v5 << (32 - 7) | v5 >>> 7;
        v0 = v0 + m2 | 0;
        v0 = v0 + v4 | 0;
        v12 ^= v0;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v8 = v8 + v12 | 0;
        v4 ^= v8;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v0 = v0 + m15 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 16) | v15 >>> 16;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 12) | v5 >>> 12;
        v1 = v1 + m9 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 16) | v12 >>> 16;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 12) | v6 >>> 12;
        v2 = v2 + m3 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 16) | v13 >>> 16;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 12) | v7 >>> 12;
        v3 = v3 + m13 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 16) | v14 >>> 16;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 12) | v4 >>> 12;
        v2 = v2 + m12 | 0;
        v2 = v2 + v7 | 0;
        v13 ^= v2;
        v13 = v13 << (32 - 8) | v13 >>> 8;
        v8 = v8 + v13 | 0;
        v7 ^= v8;
        v7 = v7 << (32 - 7) | v7 >>> 7;
        v3 = v3 + m0 | 0;
        v3 = v3 + v4 | 0;
        v14 ^= v3;
        v14 = v14 << (32 - 8) | v14 >>> 8;
        v9 = v9 + v14 | 0;
        v4 ^= v9;
        v4 = v4 << (32 - 7) | v4 >>> 7;
        v1 = v1 + m14 | 0;
        v1 = v1 + v6 | 0;
        v12 ^= v1;
        v12 = v12 << (32 - 8) | v12 >>> 8;
        v11 = v11 + v12 | 0;
        v6 ^= v11;
        v6 = v6 << (32 - 7) | v6 >>> 7;
        v0 = v0 + m11 | 0;
        v0 = v0 + v5 | 0;
        v15 ^= v0;
        v15 = v15 << (32 - 8) | v15 >>> 8;
        v10 = v10 + v15 | 0;
        v5 ^= v10;
        v5 = v5 << (32 - 7) | v5 >>> 7;

        this.h[0] ^= v0 ^ v8;
        this.h[1] ^= v1 ^ v9;
        this.h[2] ^= v2 ^ v10;
        this.h[3] ^= v3 ^ v11;
        this.h[4] ^= v4 ^ v12;
        this.h[5] ^= v5 ^ v13;
        this.h[6] ^= v6 ^ v14;
        this.h[7] ^= v7 ^ v15;
    }

    update(p: Uint8Array, offset: i32, length: i32): Blake2s {
        if (this.isFinished)
            throw new Error('update() after calling digest()');
        if (length == 0) return this

        var left = 64 - this.nx

        // Finish buffer.
        if (length > left) {
            for (var i = 0; i < left; i++) {
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

    digest (): Uint8Array {
        if (this.isFinished) return this.result;

        for (var i = this.nx; i < 64; i++) this.x[i] = 0;

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
}

export function blake2s(digestLength: i32, keyOrConfig: Uint8Array): Blake2s{
    var blake2s = new Blake2s(digestLength, keyOrConfig)
    return blake2s
}