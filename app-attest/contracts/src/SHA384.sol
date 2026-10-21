// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;
// Source: github-zktls/contracts/src/SHA384.sol (MIT).

library SHA384 {
    uint64 constant MASK = 0xFFFFFFFFFFFFFFFF;

    function hash(bytes memory data) internal pure returns (bytes memory) {
        uint64[8] memory h = [
            uint64(0xcbbb9d5dc1059ed8), 0x629a292a367cd507,
            0x9159015a3070dd17, 0x152fecd8f70e5939,
            0x67332667ffc00b31, 0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
        ];

        bytes memory padded = _pad(data);

        for (uint256 i = 0; i < padded.length; i += 128) {
            _processBlock(h, padded, i);
        }

        bytes memory result = new bytes(48);
        for (uint256 i = 0; i < 6; i++) {
            uint64 v = h[i];
            result[i * 8 + 0] = bytes1(uint8(v >> 56));
            result[i * 8 + 1] = bytes1(uint8(v >> 48));
            result[i * 8 + 2] = bytes1(uint8(v >> 40));
            result[i * 8 + 3] = bytes1(uint8(v >> 32));
            result[i * 8 + 4] = bytes1(uint8(v >> 24));
            result[i * 8 + 5] = bytes1(uint8(v >> 16));
            result[i * 8 + 6] = bytes1(uint8(v >> 8));
            result[i * 8 + 7] = bytes1(uint8(v));
        }
        return result;
    }

    function _pad(bytes memory data) private pure returns (bytes memory) {
        uint256 bitLen = data.length * 8;
        uint256 padLen = 128 - ((data.length + 17) % 128);
        if (padLen == 128) padLen = 0;
        bytes memory padded = new bytes(data.length + 1 + padLen + 16);

        for (uint256 i = 0; i < data.length; i++) {
            padded[i] = data[i];
        }
        padded[data.length] = 0x80;

        uint256 end = padded.length;
        padded[end - 1] = bytes1(uint8(bitLen));
        padded[end - 2] = bytes1(uint8(bitLen >> 8));
        padded[end - 3] = bytes1(uint8(bitLen >> 16));
        padded[end - 4] = bytes1(uint8(bitLen >> 24));
        padded[end - 5] = bytes1(uint8(bitLen >> 32));
        padded[end - 6] = bytes1(uint8(bitLen >> 40));
        padded[end - 7] = bytes1(uint8(bitLen >> 48));
        padded[end - 8] = bytes1(uint8(bitLen >> 56));

        return padded;
    }

    function _processBlock(uint64[8] memory h, bytes memory data, uint256 offset) private pure {
        uint64[80] memory w;

        for (uint256 t = 0; t < 16; t++) {
            uint256 idx = offset + t * 8;
            w[t] = (uint64(uint8(data[idx])) << 56)
                | (uint64(uint8(data[idx + 1])) << 48)
                | (uint64(uint8(data[idx + 2])) << 40)
                | (uint64(uint8(data[idx + 3])) << 32)
                | (uint64(uint8(data[idx + 4])) << 24)
                | (uint64(uint8(data[idx + 5])) << 16)
                | (uint64(uint8(data[idx + 6])) << 8)
                | uint64(uint8(data[idx + 7]));
        }

        unchecked {
            for (uint256 t = 16; t < 80; t++) {
                uint64 s0 = _rotr(w[t-15], 1) ^ _rotr(w[t-15], 8) ^ (w[t-15] >> 7);
                uint64 s1 = _rotr(w[t-2], 19) ^ _rotr(w[t-2], 61) ^ (w[t-2] >> 6);
                w[t] = (w[t-16] + s0 + w[t-7] + s1) & MASK;
            }

            uint64[8] memory v;
            for (uint256 i = 0; i < 8; i++) v[i] = h[i];

            uint64[80] memory k = _K();

            for (uint256 t = 0; t < 80; t++) {
                _round(v, k[t], w[t]);
            }

            for (uint256 i = 0; i < 8; i++) h[i] = (h[i] + v[i]) & MASK;
        }
    }

    function _round(uint64[8] memory v, uint64 ki, uint64 wi) private pure {
        unchecked {
            uint64 S1 = _rotr(v[4], 14) ^ _rotr(v[4], 18) ^ _rotr(v[4], 41);
            uint64 ch = (v[4] & v[5]) ^ ((~v[4] & MASK) & v[6]);
            uint64 temp1 = (v[7] + S1 + ch + ki + wi) & MASK;
            uint64 S0 = _rotr(v[0], 28) ^ _rotr(v[0], 34) ^ _rotr(v[0], 39);
            uint64 maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            uint64 temp2 = (S0 + maj) & MASK;

            v[7] = v[6]; v[6] = v[5]; v[5] = v[4];
            v[4] = (v[3] + temp1) & MASK;
            v[3] = v[2]; v[2] = v[1]; v[1] = v[0];
            v[0] = (temp1 + temp2) & MASK;
        }
    }

    function _rotr(uint64 x, uint8 n) private pure returns (uint64) {
        return ((x >> n) | (x << (64 - n))) & MASK;
    }

    function _K() private pure returns (uint64[80] memory) {
        return [
            uint64(0x428a2f98d728ae22), 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        ];
    }
}
