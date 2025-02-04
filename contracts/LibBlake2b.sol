// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**************************************

    Blake2b hashing library

**************************************/

// -----------------------------------------------------------------------
//                  C++ reference implementation for Blake2b
//                      Refer to Appendix C from:
//              https://datatracker.ietf.org/doc/html/rfc7693.html
// -----------------------------------------------------------------------

/// @notice This library implements Blake2b based on Consensys and Filecoin work.
library LibBlake2b {
    // -----------------------------------------------------------------------
    //                              Constants
    // -----------------------------------------------------------------------

    // RFC-7693: initialization vector
    function IV(uint256 _index) internal pure returns (uint64) {
        return
            [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179
            ][_index];
    }

    // RFC-7693: masks
    uint64 internal constant MASK_0 = 0xFF00000000000000;
    uint64 internal constant MASK_1 = 0x00FF000000000000;
    uint64 internal constant MASK_2 = 0x0000FF0000000000;
    uint64 internal constant MASK_3 = 0x000000FF00000000;
    uint64 internal constant MASK_4 = 0x00000000FF000000;
    uint64 internal constant MASK_5 = 0x0000000000FF0000;
    uint64 internal constant MASK_6 = 0x000000000000FF00;
    uint64 internal constant MASK_7 = 0x00000000000000FF;

    // RFC-7693: shifts
    uint64 internal constant SHIFT_0 = 0x0100000000000000;
    uint64 internal constant SHIFT_1 = 0x0000010000000000;
    uint64 internal constant SHIFT_2 = 0x0000000001000000;
    uint64 internal constant SHIFT_3 = 0x0000000000000100;

    // -----------------------------------------------------------------------
    //                              Structs
    // -----------------------------------------------------------------------

    /// @dev Struct containing info about current context for Blake2b hashing.
    /// @param b Input buffer
    /// @param h Chained state
    /// @param t Total bytes
    /// @param c Size of buffer
    /// @param digestSize Size of output digest
    struct Context {
        uint256[4] b;
        uint64[8] h;
        uint128 t;
        uint64 c;
        uint256 digestSize;
    }

    /// @dev Struct containing strictly typed results for Blake2b output.
    /// @param output_64 Output used for Blake2b_64 (with 8 word digest size)
    /// @param output_128 Output used for Blake2b_128 (with 16 word digest size)
    /// @param output_256 Output used for Blake2b_256 (with 32 word digest size)
    /// @param output_512 Output used for Blake2b_512 (with 64 word digest size)
    struct Output {
        uint64[1] output_64;
        uint64[2] output_128;
        uint64[4] output_256;
        uint64[8] output_512;
    }

    // -----------------------------------------------------------------------
    //                              Entrypoint
    // -----------------------------------------------------------------------

    function blake2b_64(bytes memory _input) internal pure returns (bytes32) {
        // return
        return
            sum64(
                blake2b(
                    _input,
                    "",
                    "",
                    "",
                    8 // digest size
                ).output_64
            );
    }

    function blake2b_128(bytes memory _input) internal pure returns (bytes32) {
        // return
        return
            sum128(
                blake2b(
                    _input,
                    "",
                    "",
                    "",
                    16 // digest size
                ).output_128
            );
    }

    function blake2b_256(bytes memory _input) internal pure returns (bytes32) {
        // return
        return
            sum256(
                blake2b(
                    _input,
                    "",
                    "",
                    "",
                    32 // digest size
                ).output_256
            );
    }

    function blake2b_512(bytes memory _input) internal pure returns (bytes memory) {
        // return
        return
            abi.encodePacked(
                sum512(
                    blake2b(
                        _input,
                        "",
                        "",
                        "",
                        64 // digest size
                    ).output_512
                )
            );
    }

    function blake2b(bytes memory _input, uint64 _digestSize) internal pure returns (Output memory) {
        // return
        return blake2b(_input, "", "", "", _digestSize);
    }

    function blake2b(
        bytes memory _input,
        bytes memory _key,
        bytes memory _salt,
        bytes memory _personalization,
        uint64 _digestSize
    ) internal pure returns (Output memory) {
        // declare vars
        Context memory context_;
        Output memory output_;

        // init
        _init(context_, _digestSize, _key, _formatInput(_salt), _formatInput(_personalization));

        // update
        _update(context_, _input);

        // finalize
        _finalize(context_, output_);

        // return
        return output_;
    }

    function sum64(uint64[1] memory _array) internal pure returns (bytes8) {
        // return
        return bytes8(_array[0]);
    }

    function sum128(uint64[2] memory _array) internal pure returns (bytes16) {
        // return
        return bytes16((uint128(_array[0]) << 64) | _array[1]);
    }

    function sum256(uint64[4] memory _array) internal pure returns (bytes32) {
        // compute and return
        bytes16 a_ = bytes16((uint128(_array[0]) << 64) | _array[1]);
        bytes16 b_ = bytes16((uint128(_array[2]) << 64) | _array[3]);
        return bytes32((uint256(uint128(a_)) << 128) | uint128(b_));
    }

    function sum512(uint64[8] memory _array) internal pure returns (bytes32[2] memory) {
        // compute
        bytes16 a_ = bytes16((uint128(_array[0]) << 64) | _array[1]);
        bytes16 b_ = bytes16((uint128(_array[2]) << 64) | _array[3]);
        bytes32 first_ = bytes32((uint256(uint128(a_)) << 128) | uint128(b_));
        bytes16 c_ = bytes16((uint128(_array[4]) << 64) | _array[5]);
        bytes16 d_ = bytes16((uint128(_array[6]) << 64) | _array[7]);
        bytes32 second_ = bytes32((uint256(uint128(c_)) << 128) | uint128(d_));

        // return
        return [first_, second_];
    }

    // -----------------------------------------------------------------------
    //                              Cryptography
    // -----------------------------------------------------------------------

    // @dev Mixing function
    function G(uint64[16] memory v, uint256 a, uint256 b, uint256 c, uint256 d, uint64 x, uint64 y) internal pure {
        // dereference to decrease memory reads
        uint64 va = v[a];
        uint64 vb = v[b];
        uint64 vc = v[c];
        uint64 vd = v[d];

        // optimised mixing function
        assembly {
            // v[a] := (v[a] + v[b] + x) mod 2**64
            va := addmod(add(va, vb), x, 0x10000000000000000)

            //v[d] := (v[d] ^ v[a]) >>> 32
            vd := xor(div(xor(vd, va), 0x100000000), mulmod(xor(vd, va), 0x100000000, 0x10000000000000000))

            //v[c] := (v[c] + v[d])     mod 2**64
            vc := addmod(vc, vd, 0x10000000000000000)

            //v[b] := (v[b] ^ v[c]) >>> 24
            vb := xor(div(xor(vb, vc), 0x1000000), mulmod(xor(vb, vc), 0x10000000000, 0x10000000000000000))

            // v[a] := (v[a] + v[b] + y) mod 2**64
            va := addmod(add(va, vb), y, 0x10000000000000000)

            //v[d] := (v[d] ^ v[a]) >>> 16
            vd := xor(div(xor(vd, va), 0x10000), mulmod(xor(vd, va), 0x1000000000000, 0x10000000000000000))

            //v[c] := (v[c] + v[d])     mod 2**64
            vc := addmod(vc, vd, 0x10000000000000000)

            // v[b] := (v[b] ^ v[c]) >>> 63
            vb := xor(div(xor(vb, vc), 0x8000000000000000), mulmod(xor(vb, vc), 0x2, 0x10000000000000000))
        }

        // save to buffer
        v[a] = va;
        v[b] = vb;
        v[c] = vc;
        v[d] = vd;
    }

    function _compress(Context memory _context, bool _last) internal pure {
        // args
        uint64[16] memory v;
        uint64[16] memory m;

        // loop
        for (uint256 i = 0; i < 8; i++) {
            v[i] = _context.h[i]; // v[:8] = h[:8]
            v[i + 8] = IV(i); // v[8:] = IV
        }

        v[12] = v[12] ^ uint64(_context.t % 2 ** 64); // lower word of t
        v[13] = v[13] ^ uint64(_context.t / 2 ** 64);

        // finalization flag
        if (_last) v[14] = ~v[14];

        uint64 mi; // temporary stack variable to decrease memory ops
        uint256 b; // input buffer

        for (uint256 i = 0; i < 16; i++) {
            // operate 16 words at a time
            uint256 k = i % 4; // current buffer word
            mi = 0;
            if (k == 0) {
                b = _context.b[i / 4]; // load relevant input into buffer
            }

            // extract relevant input from buffer
            assembly {
                mi := and(div(b, exp(2, mul(64, sub(3, k)))), 0xFFFFFFFFFFFFFFFF)
            }

            // flip endianness
            m[i] = _getWords(mi);
        }

        // mix m
        G(v, 0, 4, 8, 12, m[0], m[1]);
        G(v, 1, 5, 9, 13, m[2], m[3]);
        G(v, 2, 6, 10, 14, m[4], m[5]);
        G(v, 3, 7, 11, 15, m[6], m[7]);
        G(v, 0, 5, 10, 15, m[8], m[9]);
        G(v, 1, 6, 11, 12, m[10], m[11]);
        G(v, 2, 7, 8, 13, m[12], m[13]);
        G(v, 3, 4, 9, 14, m[14], m[15]);

        G(v, 0, 4, 8, 12, m[14], m[10]);
        G(v, 1, 5, 9, 13, m[4], m[8]);
        G(v, 2, 6, 10, 14, m[9], m[15]);
        G(v, 3, 7, 11, 15, m[13], m[6]);
        G(v, 0, 5, 10, 15, m[1], m[12]);
        G(v, 1, 6, 11, 12, m[0], m[2]);
        G(v, 2, 7, 8, 13, m[11], m[7]);
        G(v, 3, 4, 9, 14, m[5], m[3]);

        G(v, 0, 4, 8, 12, m[11], m[8]);
        G(v, 1, 5, 9, 13, m[12], m[0]);
        G(v, 2, 6, 10, 14, m[5], m[2]);
        G(v, 3, 7, 11, 15, m[15], m[13]);
        G(v, 0, 5, 10, 15, m[10], m[14]);
        G(v, 1, 6, 11, 12, m[3], m[6]);
        G(v, 2, 7, 8, 13, m[7], m[1]);
        G(v, 3, 4, 9, 14, m[9], m[4]);

        G(v, 0, 4, 8, 12, m[7], m[9]);
        G(v, 1, 5, 9, 13, m[3], m[1]);
        G(v, 2, 6, 10, 14, m[13], m[12]);
        G(v, 3, 7, 11, 15, m[11], m[14]);
        G(v, 0, 5, 10, 15, m[2], m[6]);
        G(v, 1, 6, 11, 12, m[5], m[10]);
        G(v, 2, 7, 8, 13, m[4], m[0]);
        G(v, 3, 4, 9, 14, m[15], m[8]);

        G(v, 0, 4, 8, 12, m[9], m[0]);
        G(v, 1, 5, 9, 13, m[5], m[7]);
        G(v, 2, 6, 10, 14, m[2], m[4]);
        G(v, 3, 7, 11, 15, m[10], m[15]);
        G(v, 0, 5, 10, 15, m[14], m[1]);
        G(v, 1, 6, 11, 12, m[11], m[12]);
        G(v, 2, 7, 8, 13, m[6], m[8]);
        G(v, 3, 4, 9, 14, m[3], m[13]);

        G(v, 0, 4, 8, 12, m[2], m[12]);
        G(v, 1, 5, 9, 13, m[6], m[10]);
        G(v, 2, 6, 10, 14, m[0], m[11]);
        G(v, 3, 7, 11, 15, m[8], m[3]);
        G(v, 0, 5, 10, 15, m[4], m[13]);
        G(v, 1, 6, 11, 12, m[7], m[5]);
        G(v, 2, 7, 8, 13, m[15], m[14]);
        G(v, 3, 4, 9, 14, m[1], m[9]);

        G(v, 0, 4, 8, 12, m[12], m[5]);
        G(v, 1, 5, 9, 13, m[1], m[15]);
        G(v, 2, 6, 10, 14, m[14], m[13]);
        G(v, 3, 7, 11, 15, m[4], m[10]);
        G(v, 0, 5, 10, 15, m[0], m[7]);
        G(v, 1, 6, 11, 12, m[6], m[3]);
        G(v, 2, 7, 8, 13, m[9], m[2]);
        G(v, 3, 4, 9, 14, m[8], m[11]);

        G(v, 0, 4, 8, 12, m[13], m[11]);
        G(v, 1, 5, 9, 13, m[7], m[14]);
        G(v, 2, 6, 10, 14, m[12], m[1]);
        G(v, 3, 7, 11, 15, m[3], m[9]);
        G(v, 0, 5, 10, 15, m[5], m[0]);
        G(v, 1, 6, 11, 12, m[15], m[4]);
        G(v, 2, 7, 8, 13, m[8], m[6]);
        G(v, 3, 4, 9, 14, m[2], m[10]);

        G(v, 0, 4, 8, 12, m[6], m[15]);
        G(v, 1, 5, 9, 13, m[14], m[9]);
        G(v, 2, 6, 10, 14, m[11], m[3]);
        G(v, 3, 7, 11, 15, m[0], m[8]);
        G(v, 0, 5, 10, 15, m[12], m[2]);
        G(v, 1, 6, 11, 12, m[13], m[7]);
        G(v, 2, 7, 8, 13, m[1], m[4]);
        G(v, 3, 4, 9, 14, m[10], m[5]);

        G(v, 0, 4, 8, 12, m[10], m[2]);
        G(v, 1, 5, 9, 13, m[8], m[4]);
        G(v, 2, 6, 10, 14, m[7], m[6]);
        G(v, 3, 7, 11, 15, m[1], m[5]);
        G(v, 0, 5, 10, 15, m[15], m[11]);
        G(v, 1, 6, 11, 12, m[9], m[14]);
        G(v, 2, 7, 8, 13, m[3], m[12]);
        G(v, 3, 4, 9, 14, m[13], m[0]);

        G(v, 0, 4, 8, 12, m[0], m[1]);
        G(v, 1, 5, 9, 13, m[2], m[3]);
        G(v, 2, 6, 10, 14, m[4], m[5]);
        G(v, 3, 7, 11, 15, m[6], m[7]);
        G(v, 0, 5, 10, 15, m[8], m[9]);
        G(v, 1, 6, 11, 12, m[10], m[11]);
        G(v, 2, 7, 8, 13, m[12], m[13]);
        G(v, 3, 4, 9, 14, m[14], m[15]);

        G(v, 0, 4, 8, 12, m[14], m[10]);
        G(v, 1, 5, 9, 13, m[4], m[8]);
        G(v, 2, 6, 10, 14, m[9], m[15]);
        G(v, 3, 7, 11, 15, m[13], m[6]);
        G(v, 0, 5, 10, 15, m[1], m[12]);
        G(v, 1, 6, 11, 12, m[0], m[2]);
        G(v, 2, 7, 8, 13, m[11], m[7]);
        G(v, 3, 4, 9, 14, m[5], m[3]);

        // XOR current state with both halves of v
        for (uint256 i = 0; i < 8; ++i) {
            _context.h[i] = _context.h[i] ^ v[i] ^ v[i + 8];
        }
    }

    function _init(
        Context memory _context,
        uint64 _digestSize,
        bytes memory _key,
        uint64[2] memory _salt,
        uint64[2] memory _person
    ) internal pure {
        // validate digest
        if (_digestSize == 0 || _digestSize > 64 || _key.length > 64) revert("Invalid digest size or key length");

        // initialize chained-state to IV
        for (uint256 i = 0; i < 8; i++) {
            _context.h[i] = IV(i);
        }

        // set up parameter block
        _context.h[0] = _context.h[0] ^ 0x01010000 ^ _shiftLeft(uint64(_key.length), 8) ^ _digestSize;
        _context.h[4] = _context.h[4] ^ _salt[0];
        _context.h[5] = _context.h[5] ^ _salt[1];
        _context.h[6] = _context.h[6] ^ _person[0];
        _context.h[7] = _context.h[7] ^ _person[1];

        // update digest size
        _context.digestSize = _digestSize;

        // run hash once with key as input
        if (_key.length > 0) {
            _update(_context, _key);
            _context.c = 128;
        }
    }

    function _update(Context memory _context, bytes memory _input) internal pure {
        // iterate over input
        for (uint256 i = 0; i < _input.length; i++) {
            // if buffer is full, update byte counters and compress
            if (_context.c == 128) {
                _context.t += _context.c;
                _compress(_context, false);
                _context.c = 0;
            }

            // update temporary counter c
            uint256 c = _context.c++;

            // b -> ctx.b
            uint256[4] memory b = _context.b;
            uint8 a = uint8(_input[i]);

            // ctx.b[c] = a
            assembly {
                mstore8(add(b, c), a)
            }
        }
    }

    function _finalize(Context memory _context, Output memory _output_) internal pure {
        // vars
        uint256 wordsNo_ = _context.digestSize / 8;

        // add any uncounted bytes
        _context.t += _context.c;

        // compress with finalization flag
        _compress(_context, true);

        // flip little to big endian and store in output buffer
        for (uint256 i = 0; i < wordsNo_; i++) {
            if (wordsNo_ == 1) {
                _output_.output_64[i] = _getWords(_context.h[i]);
            } else if (wordsNo_ == 2) {
                _output_.output_128[i] = _getWords(_context.h[i]);
            } else if (wordsNo_ <= 4) {
                _output_.output_256[i] = _getWords(_context.h[i]);
            } else if (wordsNo_ <= 8) {
                _output_.output_512[i] = _getWords(_context.h[i]);
            } else {
                revert("Invalid number of words");
            }
        }

        // properly pad output if it doesn't fill a full word
        bool remainder_ = _context.digestSize % 8 != 0;
        if (_context.digestSize < 8) {
            _output_.output_64[wordsNo_] = _shiftRight(_toLittleEndian(_context.h[wordsNo_]), 64 - 8 * (_context.digestSize % 8));
        } else if (_context.digestSize > 8 && _context.digestSize < 16 && remainder_) {
            _output_.output_128[wordsNo_] = _shiftRight(_toLittleEndian(_context.h[wordsNo_]), 64 - 8 * (_context.digestSize % 8));
        } else if (_context.digestSize > 16 && _context.digestSize < 32 && remainder_) {
            _output_.output_256[wordsNo_] = _shiftRight(_toLittleEndian(_context.h[wordsNo_]), 64 - 8 * (_context.digestSize % 8));
        } else if (_context.digestSize > 32 && _context.digestSize < 64 && remainder_) {
            _output_.output_512[wordsNo_] = _shiftRight(_toLittleEndian(_context.h[wordsNo_]), 64 - 8 * (_context.digestSize % 8));
        }
    }

    // -----------------------------------------------------------------------
    //                              Utilities
    // -----------------------------------------------------------------------

    // @dev flips endianness of words
    function _getWords(uint64 _item) internal pure returns (uint64) {
        // return
        return
            ((_item & MASK_0) / SHIFT_0) ^
            ((_item & MASK_1) / SHIFT_1) ^
            ((_item & MASK_2) / SHIFT_2) ^
            ((_item & MASK_3) / SHIFT_3) ^
            ((_item & MASK_4) * SHIFT_3) ^
            ((_item & MASK_5) * SHIFT_2) ^
            ((_item & MASK_6) * SHIFT_1) ^
            ((_item & MASK_7) * SHIFT_0);
    }

    function _toLittleEndian(uint64 _number) internal pure returns (uint64) {
        // vars
        uint64 result_;
        bytes8 _numberBytes = bytes8(_number);

        // loop
        for (uint256 i; i < 8; i++) {
            result_ = (uint64(result_ ^ (uint64(uint8(_numberBytes[i])) * (2 ** (0x08 * i)))));
        }

        // return
        return result_;
    }

    function _shiftRight(uint64 _number, uint256 _places) internal pure returns (uint64) {
        // return
        return uint64(_number / 2 ** _places);
    }

    function _shiftLeft(uint64 _base, uint256 _places) internal pure returns (uint64) {
        // return
        return uint64((_base * 2 ** _places) % (2 ** 64));
    }

    // @dev bytes -> uint64[2]
    function _formatInput(bytes memory _input) internal pure returns (uint64[2] memory) {
        // vars
        uint64[2] memory output_;

        // loop
        for (uint256 i = 0; i < _input.length; i++) {
            output_[i / 8] = (output_[i / 8] ^ _shiftLeft(uint64(uint8(_input[i])), 64 - 8 * ((i % 8) + 1)));
        }

        // get words
        output_[0] = _getWords(output_[0]);
        output_[1] = _getWords(output_[1]);

        // return
        return output_;
    }

    function _formatOutput(uint64[8] memory _input) public pure returns (bytes32[2] memory) {
        // vars
        bytes32[2] memory result_;

        // loop
        for (uint256 i = 0; i < 8; i++) {
            result_[i / 4] = (result_[i / 4] ^ bytes32(_input[i] * 2 ** (64 * (3 - (i % 4)))));
        }

        // return
        return result_;
    }
}
