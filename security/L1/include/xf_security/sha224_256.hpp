/*
 * Copyright 2019 Xilinx, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _XF_SECURITY_SHA224_256_HPP_
#define _XF_SECURITY_SHA224_256_HPP_

#include <ap_int.h>
#include <hls_stream.h>

#include "xf_security/types.hpp"
#include "xf_security/utils.hpp"

// For debug
#ifndef __SYNTHESIS__
#include <cstdio>
#endif
#ifndef _DEBUG
#define _DEBUG (0)
#endif
#define _XF_SECURITY_VOID_CAST static_cast<void>
// XXX toggle here to debug this file
#define _XF_SECURITY_PRINT(msg...) \
    do {                           \
        if (_DEBUG) printf(msg);   \
    } while (0)

#define ROTR(n, x) ((x >> n) | (x << (32 - n)))
#define ROTL(n, x) ((x << n) | (x >> (32 - n)))
#define SHR(n, x) (x >> n)
#define CH(x, y, z) ((x & y) ^ ((~x) & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x) (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x))
#define BSIG1(x) (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x))
#define SSIG0(x) (ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x))
#define SSIG1(x) (ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x))

namespace xf {
namespace security {
namespace internal {

/// Processing block
struct SHA256Block {
    uint32_t M[16];
};

/// @brief Static config for SHA224 and SHA256.
template <bool do_sha224>
struct sha256_digest_config;

template <>
struct sha256_digest_config<true> {
    static const short numH = 7;
};

template <>
struct sha256_digest_config<false> {
    static const short numH = 8;
};

#ifndef SHA256_LANES
#define SHA256_LANES 2  
#endif

/// @brief Generate 512bit processing blocks for SHA224/SHA256 (pipeline)
/// with const width.
/// The performance goal of this function is to yield a 512b block per cycle.
/// @param msg_strm the message being hashed.
/// @param len_strm the message length in byte.
/// @param end_len_strm that flag to signal end of input.
/// @param blk_strm the 512-bit hash block.
/// @param nblk_strm the number of hash block for this message.
/// @param end_nblk_strm end flag for number of hash block.
inline void preProcessing(hls::stream<ap_uint<32> >& msg_strm,
                          hls::stream<ap_uint<64> >& len_strm,
                          hls::stream<bool>& end_len_strm,
                          hls::stream<SHA256Block>& blk_strm,
                          hls::stream<uint64_t>& nblk_strm,
                          hls::stream<bool>& end_nblk_strm) {
LOOP_SHA256_GENENERATE_MAIN:
    for (bool end_flag = end_len_strm.read(); !end_flag; end_flag = end_len_strm.read()) {
        /// message length in byte.
        uint64_t len = len_strm.read();
        /// message length in bit.
        uint64_t L = 8 * len;
        /// total number blocks to digest.
        uint64_t blk_num = (len >> 6) + 1 + ((len & 0x3f) > 55);
        // inform digest function.
        nblk_strm.write(blk_num);
        end_nblk_strm.write(false);

    LOOP_SHA256_GEN_FULL_BLKS:
        for (uint64_t j = 0; j < uint64_t(len >> 6); ++j) {
#pragma HLS pipeline II = 16
#pragma HLS loop_tripcount min = 0 max = 1
            /// message block.
            SHA256Block b0;
#pragma HLS array_partition variable = b0.M complete
        // this block will hold 64 byte of message.
        LOOP_SHA256_GEN_ONE_FULL_BLK:
            for (int i = 0; i < 16; ++i) {
#pragma HLS unroll
                uint32_t l = msg_strm.read();
                // XXX algorithm assumes big-endian.
                l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8) |
                    ((0xff000000UL & l) >> 24);
                b0.M[i] = l;
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (32bx16)\n", i, b0.M[i]);
            }
            // send block
            blk_strm.write(b0);
            _XF_SECURITY_PRINT("DEBUG: block sent\n");
            // shift the buffer. high will be zero.
        }

        /// number of bytes not in blocks yet.
        char left = (char)(len & 0x3fULL); // < 64

        _XF_SECURITY_PRINT("DEBUG: sent = %d, left = %d\n", int(len & (-1ULL ^ 0x3fULL)), (int)left);

        if (left == 0) {
            // end at block boundary, start with pad 1.

            /// last block
            SHA256Block b;
#pragma HLS array_partition variable = b.M complete
            // pad 1
            b.M[0] = 0x80000000UL;
            _XF_SECURITY_PRINT("DEBUG: M[0] =\t%08x (pad 1)\n", b.M[0]);
        // zero
        LOOP_SHA256_GEN_PAD_13_ZEROS:
            for (int i = 1; i < 14; ++i) {
#pragma HLS unrolltrm
                b.M[i] = 0;
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (zero)\n", i, b.M[i]);
            }
            // append L
            b.M[14] = (uint32_t)(0xffffffffUL & (L >> 32));
            b.M[15] = (uint32_t)(0xffffffffUL & (L));
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 14, b.M[14]);
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 15, b.M[15]);
            // emit
            blk_strm.write(b);
        } else if (left < 56) {
            // can pad 1 and append L.

            // last message block.
            SHA256Block b;
#pragma HLS array_partition variable = b.M complete

        LOOP_SHA256_GEN_COPY_TAIL_AND_ONE:
            for (int i = 0; i < 14; ++i) {
#pragma HLS pipeline
                if (i < (left >> 2)) {
                    uint32_t l = msg_strm.read();
                    // pad 1 byte not in this word
                    // XXX algorithm assumes big-endian.
                    l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8) |
                        ((0xff000000UL & l) >> 24);
                    b.M[i] = l;
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (32b)\n", i, b.M[i]);
                } else if (i > (left >> 2)) {
                    // pad 1 not in this word, and no word to read.
                    b.M[i] = 0UL;
                } else {
                    // pad 1 byte in this word
                    uint32_t e = left & 3L;
                    if (e == 0) {
                        b.M[i] = 0x80000000UL;
                    } else if (e == 1) {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24);
                        b.M[i] = l | 0x00800000UL;
                    } else if (e == 2) {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8);
                        b.M[i] = l | 0x00008000UL;
                    } else {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8);
                        b.M[i] = l | 0x00000080UL;
                    }
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (pad 1)\n", i, b.M[i]);
                }
            }
            // append L
            b.M[14] = (uint32_t)(0xffffffffUL & (L >> 32));
            b.M[15] = (uint32_t)(0xffffffffUL & (L));
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 14, b.M[14]);
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 15, b.M[15]);

            blk_strm.write(b);
            _XF_SECURITY_PRINT("DEBUG: block sent\n");
        } else {
            // cannot append L.

            /// last but 1 block.
            SHA256Block b;
#pragma HLS array_partition variable = b.M complete
        // copy and pad 1
        LOOP_SHA256_GEN_COPY_TAIL_ONLY:
            for (int i = 0; i < 16; ++i) {
#pragma HLS unroll
                if (i < (left >> 2)) {
                    // pad 1 byte not in this word
                    uint32_t l = msg_strm.read();
                    // XXX algorithm assumes big-endian.
                    l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8) |
                        ((0xff000000UL & l) >> 24);
                    b.M[i] = l;
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (32b)\n", i, b.M[i]);
                } else if (i > (left >> 2)) {
                    // pad 1 byte not in this word, and no msg word to read
                    b.M[i] = 0UL;
                } else {
                    // last in this word
                    uint32_t e = left & 3L;
                    if (e == 0) {
                        b.M[i] = 0x80000000UL;
                    } else if (e == 1) {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24);
                        b.M[i] = l | 0x00800000UL;
                    } else if (e == 2) {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8);
                        b.M[i] = l | 0x00008000UL;
                    } else {
                        uint32_t l = msg_strm.read();
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8);
                        b.M[i] = l | 0x00000080UL;
                    }
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (pad 1)\n", i, b.M[i]);
                }
            }
            blk_strm.write(b);
            _XF_SECURITY_PRINT("DEBUG: block sent\n");

            /// last block.
            SHA256Block b1;
#pragma HLS array_partition variable = b1.M complete
        LOOP_SHA256_GEN_L_ONLY_BLK:
            for (int i = 0; i < 14; ++i) {
#pragma HLS unroll
                b1.M[i] = 0;
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (zero)\n", i, b1.M[i]);
            }
            // append L
            b1.M[14] = (uint32_t)(0xffffffffUL & (L >> 32));
            b1.M[15] = (uint32_t)(0xffffffffUL & (L));
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 14, b1.M[14]);
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 15, b1.M[15]);

            blk_strm.write(b1);
            _XF_SECURITY_PRINT("DEBUG: block sent\n");
        }
    } // main loop
    end_nblk_strm.write(true);

} // preProcessing (32-bit ver)

/// @brief Generate 512bit processing blocks for SHA224/SHA256 (pipeline)
/// with const width.
/// The performance goal of this function is to yield a 512b block per cycle.
/// @param msg_strm the message being hashed.
/// @param len_strm the message length in byte.
/// @param end_len_strm that flag to signal end of input.
/// @param blk_strm the 512-bit hash block.
/// @param nblk_strm the number of hash block for this message.
/// @param end_nblk_strm end flag for number of hash block.
inline void preProcessing(hls::stream<ap_uint<64> >& msg_strm,
                          hls::stream<ap_uint<64> >& len_strm,
                          hls::stream<bool>& end_len_strm,
                          hls::stream<SHA256Block>& blk_strm,
                          hls::stream<uint64_t>& nblk_strm,
                          hls::stream<bool>& end_nblk_strm) {
LOOP_SHA256_GENENERATE_MAIN:
    for (bool end_flag = end_len_strm.read(); !end_flag; end_flag = end_len_strm.read()) {
        /// message length in byte.
        uint64_t len = len_strm.read();
        _XF_SECURITY_PRINT("DEBUG: working on a new message of %ld bytes\n", len);
        /// message length in bit.
        uint64_t L = 8 * len;
        /// total number blocks to digest.
        uint64_t blk_num = (len >> 6) + 1 + ((len & 0x3f) > 55);
        // inform digest function.
        nblk_strm.write(blk_num);
        end_nblk_strm.write(false);

    LOOP_SHA256_GEN_FULL_BLKS:
        for (uint64_t j = 0; j < uint64_t(len >> 6); ++j) {
#pragma HLS pipeline II = 16 rewind
#pragma HLS loop_tripcount min = 0 max = 1
            /// message block.
            SHA256Block b0;
#pragma HLS array_partition variable = b0.M complete

        // this block will hold 64 byte of message.
        LOOP_SHA256_GEN_ONE_FULL_BLK:
            for (int i = 0; i < 16; i += 2) {
#pragma HLS unroll
                uint64_t ll = msg_strm.read().to_uint64();
                // low
                uint32_t l = ll & 0xffffffffUL;
                // XXX algorithm assumes big-endian.
                l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8) |
                    ((0xff000000UL & l) >> 24);
                b0.M[i] = l;
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (64bx8 low)\n", i, b0.M[i]);
                // high
                l = (ll >> 32) & 0xffffffffUL;
                // XXX algorithm assumes big-endian.
                l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8) |
                    ((0xff000000UL & l) >> 24);
                b0.M[i + 1] = l;
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (64bx8 high)\n", i, b0.M[i]);
            }
            // send block
            blk_strm.write(b0);
            _XF_SECURITY_PRINT("DEBUG: block sent\n");
            // shift the buffer. high will be zero.
        }

        /// number of bytes not in blocks yet.
        char left = (char)(len & 0x3fULL); // < 64

        _XF_SECURITY_PRINT("DEBUG: sent = %d, left = %d\n", int(len & (-1ULL ^ 0x3fULL)), (int)left);

        if (left == 0) {
            // end at block boundary, start with pad 1.

            /// last block
            SHA256Block b;
#pragma HLS array_partition variable = b.M complete
            // pad 1
            b.M[0] = 0x80000000UL;
            _XF_SECURITY_PRINT("DEBUG: M[0] =\t%08x (pad 1)\n", b.M[0]);
        // zero
        LOOP_SHA256_GEN_PAD_13_ZEROS:
            for (int i = 1; i < 14; ++i) {
#pragma HLS unroll
                b.M[i] = 0;
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (zero)\n", i, b.M[i]);
            }
            // append L
            b.M[14] = (uint32_t)(0xffffffffUL & (L >> 32));
            b.M[15] = (uint32_t)(0xffffffffUL & (L));
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 14, b.M[14]);
            _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 15, b.M[15]);
            // emit
            blk_strm.write(b);
            _XF_SECURITY_PRINT("DEBUG: block sent\n");
        } else {
            // can pad 1 and append L.

            // last message block.
            SHA256Block b;
#pragma HLS array_partition variable = b.M complete

        LOOP_SHA256_GEN_COPY_TAIL_PAD_ONE:
            for (int i = 0; i < ((left < 56) ? 7 : 8); ++i) {
#pragma HLS pipeline
                if (i < (left >> 3)) {
                    // pad 1 not in this 64b word, and need to copy
                    uint64_t ll = msg_strm.read().to_uint64();
                    // low
                    uint32_t l = ll & 0xffffffffUL;
                    // XXX algorithm assumes big-endian.
                    l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8) |
                        ((0xff000000UL & l) >> 24);
                    b.M[i * 2] = l;
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (64b low)\n", i * 2, b.M[i * 2]);
                    // high
                    l = (ll >> 32) & 0xffffffffUL;
                    // XXX algorithm assumes big-endian.
                    l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8) |
                        ((0xff000000UL & l) >> 24);
                    b.M[i * 2 + 1] = l;
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (64b high)\n", i * 2 + 1, b.M[i * 2 + 1]);
                } else if (i > (left >> 3)) {
                    // pad 1 not in this 64b word, and no word to read.
                    b.M[i * 2] = 0UL;
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (zero)\n", i * 2, b.M[i * 2]);
                    b.M[i * 2 + 1] = 0UL;
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (zero)\n", i * 2 + 1, b.M[i * 2 + 1]);
                } else {
                    // pad 1 byte in this 64b word
                    if ((left & 4) == 0) {
                        // left in low 32b
                        uint32_t e = left & 3L;
                        if (e == 0) {
                            b.M[i * 2] = 0x80000000UL;
                        } else if (e == 1) {
                            uint32_t l = msg_strm.read().to_uint64() & 0xffffffffUL;
                            // XXX algorithm assumes big-endian.
                            l = ((0x000000ffUL & l) << 24);
                            b.M[i * 2] = l | 0x00800000UL;
                        } else if (e == 2) {
                            uint32_t l = msg_strm.read().to_uint64() & 0xffffffffUL;
                            // XXX algorithm assumes big-endian.
                            l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8);
                            b.M[i * 2] = l | 0x00008000UL;
                        } else {
                            uint32_t l = msg_strm.read().to_uint64() & 0xffffffffUL;
                            // XXX algorithm assumes big-endian.
                            l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8);
                            b.M[i * 2] = l | 0x00000080UL;
                        }
                        _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (pad 1)\n", i * 2, b.M[i * 2]);
                        // high
                        b.M[i * 2 + 1] = 0UL;
                        _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (zero)\n", i * 2 + 1, b.M[i * 2 + 1]);
                    } else {
                        // left in high 32b
                        uint64_t ll = msg_strm.read().to_uint64();
                        // low 32b
                        uint32_t l = ll & 0xffffffffUL;
                        // XXX algorithm assumes big-endian.
                        l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8) |
                            ((0xff000000UL & l) >> 24);
                        b.M[i * 2] = l;
                        _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (64b low)\n", i, b.M[i * 2]);
                        // high 32b
                        l = (ll >> 32) & 0xffffffffUL;
                        uint32_t e = left & 3L;
                        if (e == 0) {
                            b.M[i * 2 + 1] = 0x80000000UL;
                        } else if (e == 1) {
                            // XXX algorithm assumes big-endian.
                            l = ((0x000000ffUL & l) << 24);
                            b.M[i * 2 + 1] = l | 0x00800000UL;
                        } else if (e == 2) {
                            // XXX algorithm assumes big-endian.
                            l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8);
                            b.M[i * 2 + 1] = l | 0x00008000UL;
                        } else {
                            // XXX algorithm assumes big-endian.
                            l = ((0x000000ffUL & l) << 24) | ((0x0000ff00UL & l) << 8) | ((0x00ff0000UL & l) >> 8);
                            b.M[i * 2 + 1] = l | 0x00000080UL;
                        }
                        _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (pad 1)\n", i * 2 + 1, b.M[i * 2 + 1]);
                    }
                }
            }

            if (left < 56) {
                // append L
                b.M[14] = (uint32_t)(0xffffffffUL & (L >> 32));
                b.M[15] = (uint32_t)(0xffffffffUL & (L));
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 14, b.M[14]);
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 15, b.M[15]);

                blk_strm.write(b);
                _XF_SECURITY_PRINT("DEBUG: block sent\n");
            } else {
                // send block without L
                blk_strm.write(b);
                _XF_SECURITY_PRINT("DEBUG: block sent\n");

                /// last block.
                SHA256Block b1;
#pragma HLS array_partition variable = b1.M complete
            LOOP_SHA256_GEN_L_ONLY_BLK:
                for (int i = 0; i < 14; ++i) {
#pragma HLS unroll
                    b1.M[i] = 0;
                    _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (zero)\n", i, b1.M[i]);
                }
                // append L
                b1.M[14] = (uint32_t)(0xffffffffUL & (L >> 32));
                b1.M[15] = (uint32_t)(0xffffffffUL & (L));
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 14, b1.M[14]);
                _XF_SECURITY_PRINT("DEBUG: M[%d] =\t%08x (append L)\n", 15, b1.M[15]);

                blk_strm.write(b1);
                _XF_SECURITY_PRINT("DEBUG: block sent\n");
            } // left < 56
        }
    } // main loop
    end_nblk_strm.write(true);

} // preProcessing (64bit ver)

inline void dup_strm(hls::stream<uint64_t>& in_strm,
                     hls::stream<bool>& in_e_strm,
                     hls::stream<uint64_t>& out1_strm,
                     hls::stream<bool>& out1_e_strm,
                     hls::stream<uint64_t>& out2_strm,
                     hls::stream<bool>& out2_e_strm) {
    bool e = in_e_strm.read();

    while (!e) {
#pragma HLS loop_tripcount min = 1 max = 1 avg = 1
#pragma HLS pipeline II = 1
        uint64_t in_r = in_strm.read();

        out1_strm.write(in_r);
        out1_e_strm.write(false);
        out2_strm.write(in_r);
        out2_e_strm.write(false);

        e = in_e_strm.read();
    }

    out1_e_strm.write(true);
    out2_e_strm.write(true);
}

// ========================= W 生成（保持 II=1，不改功能） ======================
// -----------------------------------------------------------------------------
// HLS-SHA256 v3.1 (Plan B+E)
// 功能：消除 dup_strm；在 W 流旁路输出块/消息边界：
//       - w_blk_last_strm：每块 1 次；true=该块为该消息最后一块
//       - msg_eos_strm   ：每消息 1 次 false，所有消息结束额外 1 次 true
// 设计：环形 16 槽 W 缓冲；t<16 取块；t>=16 用 σ0/σ1 + 两级加法树生成 Wt
// 约束：不跨块保留状态；II=1；pragma 全在函数体内（UG1399）
// -----------------------------------------------------------------------------
inline void generateMsgSchedule(hls::stream<SHA256Block>& blk_strm,
                                hls::stream<uint64_t>&    nblk_strm,
                                hls::stream<bool>&        end_nblk_strm,
                                hls::stream<uint32_t>&    w_strm,
                                hls::stream<bool>&        w_blk_last_strm,
                                hls::stream<bool>&        msg_eos_strm) {
#pragma HLS INLINE off
#pragma HLS BIND_OP op=add impl=dsp latency=1
    bool e = end_nblk_strm.read();

GEN_MS_MSG:
    while (!e) {
        // —— 消息起始：发出“还有消息”标记（false）
        msg_eos_strm.write(false);

        uint64_t n = nblk_strm.read();

    GEN_MS_PER_BLOCK:
        for (uint64_t i = 0; i < n; ++i) {
#pragma HLS loop_tripcount min=1 max=1
            SHA256Block blk = blk_strm.read();
#pragma HLS ARRAY_PARTITION variable=blk.M complete

            uint32_t W[16];
#pragma HLS ARRAY_PARTITION variable=W complete

        GEN_W64:
            for (int t = 0; t < 64; ++t) {
#pragma HLS PIPELINE II=1 rewind
                uint32_t Wt;
                if (t < 16) {
                    Wt   = blk.M[t];
                    W[t] = Wt;
                } else {
                    uint32_t w0  = W[(t - 16) & 15];
                    uint32_t w1  = W[(t - 15) & 15];
                    uint32_t w9  = W[(t - 7)  & 15];
                    uint32_t w14 = W[(t - 2)  & 15];

                    uint32_t s0   = SSIG0(w1);
                    uint32_t s1   = SSIG1(w14);
                    uint32_t tmp0 = s1 + w9;
                    uint32_t tmp1 = s0 + w0;
                    Wt            = tmp0 + tmp1;

                    W[t & 15] = Wt;
                }
                w_strm.write(Wt);
            }
            // —— 每块结束：告诉 Digest 该块是否为消息最后一块
            w_blk_last_strm.write(i == (n - 1));
        }

        e = end_nblk_strm.read();
    }

    // —— 所有消息结束：发送一次 true 作为 EOS
    msg_eos_strm.write(true);
}

// ================== 单轮迭代：更浅的布尔+DSP加法树 ==================
// HLS-SHA256 v3.4EP (Estimated Pressure)
// 目的：在不改 II/Latency 的前提下，压缩单拍关键路径：
//  - CH/MAJ 使用浅逻辑等价式（更利于 LUT6 映射）
//  - Σ0/Σ1 显式两级 XOR 树
//  - 指定加法在 DSP48 上实现（BIND_OP op=add impl=dsp）
// 约束：功能等价；II=1；pragma 全在函数体内
inline void sha256_iter(uint32_t& a,
                        uint32_t& b,
                        uint32_t& c,
                        uint32_t& d,
                        uint32_t& e,
                        uint32_t& f,
                        uint32_t& g,
                        uint32_t& h,
                        hls::stream<uint32_t>& w_strm,
                        uint32_t& Kt,
                        const uint32_t K[],
                        short t) {
#pragma HLS INLINE
#pragma HLS BIND_OP op=add impl=dsp latency=1   // 所有本作用域加法优先用 DSP48

    // ---- 读入当前 Wt ----
    uint32_t Wt = w_strm.read();

    // ---- Σ1(e)：(ROTR^ROTR)^ROTR，显式两级 XOR 树，减少组合深度 ----
    uint32_t e_r6  = (e >> 6)  | (e << (32 - 6));
    uint32_t e_r11 = (e >> 11) | (e << (32 - 11));
    uint32_t e_r25 = (e >> 25) | (e << (32 - 25));
    uint32_t s1a   = e_r6 ^ e_r11;
    uint32_t s1    = s1a  ^ e_r25;

    // ---- CH(e,f,g) 浅逻辑：g ^ (e & (f ^ g))（两级）----
    uint32_t fg_x  = f ^ g;
    uint32_t ch    = g ^ (e & fg_x);

    // ---- Σ0(a) 与 MAJ(a,b,c) 也走浅逻辑 & 两级 XOR ----
    uint32_t a_r2  = (a >> 2)  | (a << (32 - 2));
    uint32_t a_r13 = (a >> 13) | (a << (32 - 13));
    uint32_t a_r22 = (a >> 22) | (a << (32 - 22));
    uint32_t s0a   = a_r2 ^ a_r13;
    uint32_t s0    = s0a ^ a_r22;

    // MAJ(a,b,c) 等价式：(a & b) ^ (c & (a ^ b))（两级）
    uint32_t ab_x  = a ^ b;
    uint32_t maj   = (a & b) ^ (c & ab_x);

    // ---- 加法树：保持 3 层，映射到 DSP48 ----
    uint32_t t1a = h + s1;      // 1 级
    uint32_t t1b = ch + Kt;     // 1 级
    uint32_t t1c = t1a + t1b;   // 2 级
    uint32_t T1  = t1c + Wt;    // 3 级（最长链，置于 DSP）
    uint32_t T2  = s0 + maj;    // <=2 级

    // ---- 状态更新（同功能，不增拍）----
    uint32_t nh = g;
    uint32_t ng = f;
    uint32_t nf = e;
    uint32_t ne = d + T1;
    uint32_t nd = c;
    uint32_t nc = b;
    uint32_t nb = a;
    uint32_t na = T1 + T2;

    h = nh; g = ng; f = nf; e = ne;
    d = nd; c = nc; b = nb; a = na;

    // 下一拍的常量（保持原逻辑）
    Kt = K[(t + 1) & 63];
}

// =============================== Digest 主体（II=1） ==========================
// -----------------------------------------------------------------------------
// HLS-SHA256 v3.1 (Plan B+E)
// 功能：按 W 侧提供的边带流消费数据：
//       - 外层以 msg_eos_strm 控制消息边界（false=有下一条消息；true=结束）
//       - 内层以 w_blk_last_strm 控制块边界（true=该块为该消息最后一块）
// 约束：64 轮主循环 II=1；不跨块状态 MUX；pragma 在函数体内
// -----------------------------------------------------------------------------
template <int h_width>
void sha256Digest_onW(hls::stream<uint32_t>&          w_strm,
                      hls::stream<bool>&              w_blk_last_strm,
                      hls::stream<bool>&              msg_eos_strm,
                      hls::stream<ap_uint<h_width> >& hash_strm,
                      hls::stream<bool>&              end_hash_strm) {
#pragma HLS INLINE off
#pragma HLS BIND_OP op=add impl=dsp latency=1  
    XF_SECURITY_STATIC_ASSERT((h_width == 256) || (h_width == 224),
                              "Unsupported hash stream width, must be 224 or 256");

    static const uint32_t K[64] = {
        0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
        0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
        0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
        0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
        0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
        0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
        0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL};
#pragma HLS array_partition variable=K complete

    // —— 外层：逐消息（由 msg_eos_strm 控制）
MSG_LOOP:
    for (bool eos = msg_eos_strm.read(); !eos; eos = msg_eos_strm.read()) {

        uint32_t H[8];
#pragma HLS array_partition variable=H complete
        if (h_width == 224) {
            H[0] = 0xc1059ed8UL; H[1] = 0x367cd507UL; H[2] = 0x3070dd17UL; H[3] = 0xf70e5939UL;
            H[4] = 0xffc00b31UL; H[5] = 0x68581511UL; H[6] = 0x64f98fa7UL; H[7] = 0xbefa4fa4UL;
        } else {
            H[0] = 0x6a09e667UL; H[1] = 0xbb67ae85UL; H[2] = 0x3c6ef372UL; H[3] = 0xa54ff53aUL;
            H[4] = 0x510e527fUL; H[5] = 0x9b05688cUL; H[6] = 0x1f83d9abUL; H[7] = 0x5be0cd19UL;
        }

        // —— 内层：逐块（由 w_blk_last_strm 控制）
        bool blk_last = false;
        do {
            uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
            uint32_t e_ = H[4], f = H[5], g = H[6], h = H[7];

            uint32_t Kt = K[0];
        LOOP_SHA256_UPDATE_64_ROUNDS_ONW:
            for (short t = 0; t < 64; ++t) {
#pragma HLS pipeline II=1 rewind
                sha256_iter(a, b, c, d, e_, f, g, h, w_strm, Kt, K, t);
            }

            H[0] = a + H[0]; H[1] = b + H[1]; H[2] = c + H[2]; H[3] = d + H[3];
            H[4] = e_ + H[4]; H[5] = f + H[5]; H[6] = g + H[6]; H[7] = h + H[7];

            blk_last = w_blk_last_strm.read(); // 当前块是否为消息最后一块
        } while (!blk_last);

        // —— 输出该消息的 Hash（与原功能等价）
        if (h_width == 224) {
            ap_uint<224> w224;
        LOOP_EMIT_H224_ONW:
            for (short i = 0; i < sha256_digest_config<true>::numH; ++i) {
#pragma HLS unroll
                uint32_t l = H[i];
                uint8_t t0 = (((l) >> 24) & 0xff);
                uint8_t t1 = (((l) >> 16) & 0xff);
                uint8_t t2 = (((l) >> 8) & 0xff);
                uint8_t t3 = (((l)) & 0xff);
                uint32_t l_little = ((uint32_t)t0) | (((uint32_t)t1) << 8) | (((uint32_t)t2) << 16) | (((uint32_t)t3) << 24);
                w224.range(32 * i + 31, 32 * i) = l_little;
            }
            hash_strm.write(w224);
        } else {
            ap_uint<256> w256;
        LOOP_EMIT_H256_ONW:
            for (short i = 0; i < sha256_digest_config<false>::numH; ++i) {
#pragma HLS unroll
                uint32_t l = H[i];
                uint8_t t0 = (((l) >> 24) & 0xff);
                uint8_t t1 = (((l) >> 16) & 0xff);
                uint8_t t2 = (((l) >> 8) & 0xff);
                uint8_t t3 = (((l)) & 0xff);
                uint32_t l_little = ((uint32_t)t0) | (((uint32_t)t1) << 8) | (((uint32_t)t2) << 16) | (((uint32_t)t3) << 24);
                w256.range(32 * i + 31, 32 * i) = l_little;
            }
            hash_strm.write(w256);
        }
        end_hash_strm.write(false); // 每消息一个 false
    }
    end_hash_strm.write(true);      // 全部结束一个 true（EOS）
}

// ========================= 多 lane：分发与收集（新增） ========================
template <int LANES>
static void sha256_dispatch(hls::stream<SHA256Block>& blk_in,
                            hls::stream<uint64_t>& nblk_in,
                            hls::stream<bool>& end_in,
                            hls::stream<SHA256Block> blk_out[LANES],
                            hls::stream<uint64_t> nblk_out[LANES],
                            hls::stream<bool> end_out[LANES],
                            hls::stream<ap_uint<8> >& order_lane,
                            hls::stream<bool>& order_end) {
    // v2.1: 整消息轮询分发，消息内所有块固定到同一 lane；避免跨块状态选择
#pragma HLS INLINE off
#pragma HLS PIPELINE II=1 rewind
#pragma HLS ARRAY_PARTITION variable=blk_out complete
#pragma HLS ARRAY_PARTITION variable=nblk_out complete
#pragma HLS ARRAY_PARTITION variable=end_out complete

    bool e = end_in.read();
    ap_uint<8> rr = 0;

    while (!e) {
        uint64_t nblk = nblk_in.read();
        ap_uint<8> lane = rr;
        rr = (rr + 1) % (ap_uint<8>)LANES;

        end_out[(int)lane].write(false);
        nblk_out[(int)lane].write(nblk);

        for (uint64_t i = 0; i < nblk; ++i) {
#pragma HLS PIPELINE II=1 rewind
            blk_out[(int)lane].write(blk_in.read());
        }

        // 输出顺序通道：先 false 后 lane id（收集侧按此配对）
        order_end.write(false);
        order_lane.write(lane);

        e = end_in.read();
    }

    // 终止：每个 lane 一个 true；顺序通道一个 true
    for (int i = 0; i < LANES; ++i) {
#pragma HLS UNROLL
        end_out[i].write(true);
    }
    order_end.write(true);
}

template <int h_width, int LANES>
static void sha256_collect(hls::stream<ap_uint<h_width> > hash_in[LANES],
                           hls::stream<bool> end_in[LANES],
                           hls::stream<ap_uint<h_width> >& hash_out,
                           hls::stream<bool>& end_out,
                           hls::stream<ap_uint<8> >& order_lane,
                           hls::stream<bool>& order_end) {
    // v2.1: 按输入顺序合并各 lane 的 hash；不触碰 lane 内部状态
#pragma HLS INLINE off
#pragma HLS PIPELINE II=1 rewind
#pragma HLS ARRAY_PARTITION variable=hash_in complete
#pragma HLS ARRAY_PARTITION variable=end_in  complete

    while (true) {
        bool oe = order_end.read();
        if (oe) break;
        ap_uint<8> lane = order_lane.read();

        ap_uint<h_width> h = hash_in[(int)lane].read();
        hash_out.write(h);

        (void)end_in[(int)lane].read(); // 消费该消息对应的 false
        end_out.write(false);
    }

    // 每个 lane 末尾各有一个 true，统一消费并发出全局 true
    for (int i = 0; i < LANES; ++i) {
#pragma HLS UNROLL
        (void)end_in[i].read();
    }
    end_out.write(true);
}



/// @brief SHA-256/224 implementation top overload for ap_uint input.
/// @tparam m_width the input message stream width.
/// @tparam h_width the output hash stream width.
/// @param msg_strm the message being hashed.
/// @param len_strm the length message being hashed in byte.
/// @param end_len_strm end flag stream of input, one per message.
/// @param hash_strm the result.
/// @param end_hash_strm end falg stream of output, one per hash.
// -----------------------------------------------------------------------------
// HLS-SHA256 v2.2 (sha256_top only)
// 目的：修正 pragma 对数组元素的绑定方式，消除
//   ERROR: [HLS 207-5503] The expression must be a constant integer
// 策略：仍然是 preprocess → dispatch → (2 lanes of {W→Digest}) → collect
//       - 每条消息固定到一个 lane，避免跨块状态大MUX
//       - Digest 64轮循环保持 II=1
//       - sha256_iter 使用平衡加法树，避免长加法链
// 注意：假设 SHA256_LANES == 2。若你以后改成 3/4，需要按同样模式再手写一份 [2]/[3] 的 pragma。
// -----------------------------------------------------------------------------

// =============================== 顶层数据流并行 ===============================
// -----------------------------------------------------------------------------
// HLS-SHA256 v3.1 (Plan B+E)
// 功能：去除 dup_strm；W 端输出块/消息边界，Digest 端按边带流消费；
//       关键 FIFO（w/hash）加深并用 FIFO_SRL，缓解背压小气泡，降低 Latency。
// 约束：端口/功能不变；pragma 在函数体内；DATAFLOW 保持。
// -----------------------------------------------------------------------------
template <int m_width, int h_width>
inline void sha256_top(hls::stream<ap_uint<m_width> >& msg_strm,
                       hls::stream<ap_uint<64> >&     len_strm,
                       hls::stream<bool>&             end_len_strm,
                       hls::stream<ap_uint<h_width> >& hash_strm,
                       hls::stream<bool>&             end_hash_strm) {
#pragma HLS DATAFLOW

    // -------- Stage 0: 预处理（保持不变） --------
    hls::stream<SHA256Block> blk_strm("blk_strm");
    hls::stream<uint64_t>    nblk_strm("nblk_strm");
    hls::stream<bool>        end_nblk_strm("end_nblk_strm");
    {
#pragma HLS STREAM   variable=blk_strm      depth=64
#pragma HLS STREAM   variable=nblk_strm     depth=32
#pragma HLS STREAM   variable=end_nblk_strm depth=32
// #pragma HLS RESOURCE variable=blk_strm      core=FIFO_LUTRAM
// #pragma HLS RESOURCE variable=nblk_strm     core=FIFO_LUTRAM
// #pragma HLS RESOURCE variable=end_nblk_strm core=FIFO_LUTRAM
// v3.6CP: 宽 FIFO 一律映射到 BRAM，避免 RAM64M 的超大地址扇出
#pragma HLS RESOURCE     variable=blk_strm      core=FIFO_BRAM
#pragma HLS BIND_STORAGE variable=blk_strm      type=fifo impl=bram
// 窄控制流保持原样（也可留 LUTRAM，不在临界路径）
#pragma HLS RESOURCE     variable=nblk_strm     core=FIFO_LUTRAM
#pragma HLS RESOURCE     variable=end_nblk_strm core=FIFO_LUTRAM
    }

    preProcessing(msg_strm, len_strm, end_len_strm, blk_strm, nblk_strm, end_nblk_strm);

    // -------- Stage 1: 分发 dispatcher（保持不变） --------
    hls::stream<SHA256Block> blk_lane[SHA256_LANES];
    hls::stream<uint64_t>    nblk_lane[SHA256_LANES];
    hls::stream<bool>        end_lane[SHA256_LANES];
#pragma HLS ARRAY_PARTITION variable=blk_lane complete
#pragma HLS ARRAY_PARTITION variable=nblk_lane complete
#pragma HLS ARRAY_PARTITION variable=end_lane complete

#if SHA256_LANES > 0
#pragma HLS STREAM   variable=blk_lane[0] depth=64
#pragma HLS STREAM   variable=nblk_lane[0] depth=32
#pragma HLS STREAM   variable=end_lane[0]  depth=32
// #pragma HLS RESOURCE variable=blk_lane[0] core=FIFO_LUTRAM
// #pragma HLS RESOURCE variable=nblk_lane[0] core=FIFO_LUTRAM
// #pragma HLS RESOURCE variable=end_lane[0]  core=FIFO_LUTRAM
    // v3.6CP: lane 内的宽 blk FIFO 也改 BRAM
#pragma HLS RESOURCE     variable=blk_lane[0] core=FIFO_BRAM
#pragma HLS BIND_STORAGE variable=blk_lane[0] type=fifo impl=bram
#pragma HLS RESOURCE     variable=nblk_lane[0] core=FIFO_LUTRAM
#pragma HLS RESOURCE     variable=end_lane[0]  core=FIFO_LUTRAM
#endif
#if SHA256_LANES > 1
#pragma HLS STREAM   variable=blk_lane[1] depth=64
#pragma HLS STREAM   variable=nblk_lane[1] depth=32
#pragma HLS STREAM   variable=end_lane[1]  depth=32
// #pragma HLS RESOURCE variable=blk_lane[1] core=FIFO_LUTRAM
// #pragma HLS RESOURCE variable=nblk_lane[1] core=FIFO_LUTRAM
// #pragma HLS RESOURCE variable=end_lane[1]  core=FIFO_LUTRAM
#pragma HLS RESOURCE     variable=blk_lane[1] core=FIFO_BRAM
#pragma HLS BIND_STORAGE variable=blk_lane[1] type=fifo impl=bram
#pragma HLS RESOURCE     variable=nblk_lane[1] core=FIFO_LUTRAM
#pragma HLS RESOURCE     variable=end_lane[1]  core=FIFO_LUTRAM
#endif
#if SHA256_LANES > 2
#pragma HLS STREAM   variable=blk_lane[2] depth=64
#pragma HLS STREAM   variable=nblk_lane[2] depth=32
#pragma HLS STREAM   variable=end_lane[2]  depth=32
#pragma HLS RESOURCE variable=blk_lane[2] core=FIFO_LUTRAM
#pragma HLS RESOURCE variable=nblk_lane[2] core=FIFO_LUTRAM
#pragma HLS RESOURCE variable=end_lane[2]  core=FIFO_LUTRAM
#endif
#if SHA256_LANES > 3
#pragma HLS STREAM   variable=blk_lane[3] depth=64
#pragma HLS STREAM   variable=nblk_lane[3] depth=32
#pragma HLS STREAM   variable=end_lane[3]  depth=32
#pragma HLS RESOURCE variable=blk_lane[3] core=FIFO_LUTRAM
#pragma HLS RESOURCE variable=nblk_lane[3] core=FIFO_LUTRAM
#pragma HLS RESOURCE variable=end_lane[3]  core=FIFO_LUTRAM
#endif

    hls::stream<ap_uint<8> > order_lane("order_lane");
    hls::stream<bool>        order_end("order_end");
    {
#pragma HLS STREAM   variable=order_lane depth=32
#pragma HLS STREAM   variable=order_end  depth=8
#pragma HLS RESOURCE variable=order_lane core=FIFO_LUTRAM
#pragma HLS RESOURCE variable=order_end  core=FIFO_LUTRAM
    }

    sha256_dispatch<SHA256_LANES>(blk_strm, nblk_strm, end_nblk_strm,
                                  blk_lane, nblk_lane, end_lane,
                                  order_lane, order_end);

    // -------- Stage 2: 每 lane 的 W 生成 + Digest（无 dup_strm） --------
    hls::stream<uint32_t>          w_lane[SHA256_LANES];
    hls::stream<bool>              w_blk_last_lane[SHA256_LANES];
    hls::stream<bool>              msg_eos_lane[SHA256_LANES];
    hls::stream<ap_uint<h_width> > hash_lane[SHA256_LANES];
    hls::stream<bool>              ehash_lane[SHA256_LANES];
#pragma HLS ARRAY_PARTITION variable=w_lane         complete
#pragma HLS ARRAY_PARTITION variable=w_blk_last_lane complete
#pragma HLS ARRAY_PARTITION variable=msg_eos_lane   complete
#pragma HLS ARRAY_PARTITION variable=hash_lane      complete
#pragma HLS ARRAY_PARTITION variable=ehash_lane     complete

// —— 方案E：关键 FIFO 加深并使用 SRL 实现（减小背压、提升并行吞吐）
#if SHA256_LANES > 0
#pragma HLS STREAM   variable=w_lane[0]         depth=128
#pragma HLS STREAM   variable=w_blk_last_lane[0] depth=32
#pragma HLS STREAM   variable=msg_eos_lane[0]    depth=16
#pragma HLS STREAM   variable=hash_lane[0]       depth=32
#pragma HLS STREAM   variable=ehash_lane[0]      depth=8

#pragma HLS RESOURCE variable=w_lane[0]         core=FIFO_SRL
#pragma HLS RESOURCE variable=w_blk_last_lane[0] core=FIFO_SRL
#pragma HLS RESOURCE variable=msg_eos_lane[0]    core=FIFO_SRL
#pragma HLS RESOURCE variable=hash_lane[0]       core=FIFO_SRL
#pragma HLS RESOURCE variable=ehash_lane[0]      core=FIFO_LUTRAM
#endif
#if SHA256_LANES > 1
#pragma HLS STREAM   variable=w_lane[1]         depth=128
#pragma HLS STREAM   variable=w_blk_last_lane[1] depth=32
#pragma HLS STREAM   variable=msg_eos_lane[1]    depth=16
#pragma HLS STREAM   variable=hash_lane[1]       depth=32
#pragma HLS STREAM   variable=ehash_lane[1]      depth=8

#pragma HLS RESOURCE variable=w_lane[1]         core=FIFO_SRL
#pragma HLS RESOURCE variable=w_blk_last_lane[1] core=FIFO_SRL
#pragma HLS RESOURCE variable=msg_eos_lane[1]    core=FIFO_SRL
#pragma HLS RESOURCE variable=hash_lane[1]       core=FIFO_SRL
#pragma HLS RESOURCE variable=ehash_lane[1]      core=FIFO_LUTRAM
#endif
#if SHA256_LANES > 2
#pragma HLS STREAM   variable=w_lane[2]         depth=128
#pragma HLS STREAM   variable=w_blk_last_lane[2] depth=32
#pragma HLS STREAM   variable=msg_eos_lane[2]    depth=16
#pragma HLS STREAM   variable=hash_lane[2]       depth=32
#pragma HLS STREAM   variable=ehash_lane[2]      depth=8

#pragma HLS RESOURCE variable=w_lane[2]         core=FIFO_SRL
#pragma HLS RESOURCE variable=w_blk_last_lane[2] core=FIFO_SRL
#pragma HLS RESOURCE variable=msg_eos_lane[2]    core=FIFO_SRL
#pragma HLS RESOURCE variable=hash_lane[2]       core=FIFO_SRL
#pragma HLS RESOURCE variable=ehash_lane[2]      core=FIFO_LUTRAM
#endif
#if SHA256_LANES > 3
#pragma HLS STREAM   variable=w_lane[3]         depth=128
#pragma HLS STREAM   variable=w_blk_last_lane[3] depth=32
#pragma HLS STREAM   variable=msg_eos_lane[3]    depth=16
#pragma HLS STREAM   variable=hash_lane[3]       depth=32
#pragma HLS STREAM   variable=ehash_lane[3]      depth=8

#pragma HLS RESOURCE variable=w_lane[3]         core=FIFO_SRL
#pragma HLS RESOURCE variable=w_blk_last_lane[3] core=FIFO_SRL
#pragma HLS RESOURCE variable=msg_eos_lane[3]    core=FIFO_SRL
#pragma HLS RESOURCE variable=hash_lane[3]       core=FIFO_SRL
#pragma HLS RESOURCE variable=ehash_lane[3]      core=FIFO_LUTRAM
#endif

DUP_AND_RUN_LANES_ONW:
    for (int li = 0; li < SHA256_LANES; ++li) {
#pragma HLS UNROLL
        // —— 无 dup_strm：W 生成直接输出边带，Digest 直接消费
        generateMsgSchedule(
            blk_lane[li],
            nblk_lane[li],
            end_lane[li],
            w_lane[li],
            w_blk_last_lane[li],
            msg_eos_lane[li]);

        sha256Digest_onW<h_width>(
            w_lane[li],
            w_blk_last_lane[li],
            msg_eos_lane[li],
            hash_lane[li],
            ehash_lane[li]);
    }

    // -------- Stage 3: 合并 lane 输出（保持不变） --------
    sha256_collect<h_width, SHA256_LANES>(
        hash_lane, ehash_lane,
        hash_strm, end_hash_strm,
        order_lane, order_end);
}

} // namespace internal

/// @brief SHA-224 algorithm with ap_uint stream input and output.
/// @tparam m_width the input message stream width, currently only 32 allowed.
/// @param msg_strm the message being hashed.
/// @param len_strm the length message being hashed.
/// @param end_len_strm the flag for end of message length input.
/// @param hash_strm the result.
/// @param end_hash_strm the flag for end of hash output.
template <int m_width>
void sha224(hls::stream<ap_uint<m_width> >& msg_strm,      // in
            hls::stream<ap_uint<64> >& len_strm,           // in
            hls::stream<bool>& end_len_strm,               // in
            hls::stream<ap_uint<224> >& hash_strm,         // out
            hls::stream<bool>& end_hash_strm) {            // out
    internal::sha256_top(msg_strm, len_strm, end_len_strm, // in
                         hash_strm, end_hash_strm);        // out
}

/// @brief SHA-256 algorithm with ap_uint stream input and output.
/// @tparam m_width the input message stream width, currently only 32 allowed.
/// @param msg_strm the message being hashed.
/// @param len_strm the length message being hashed.
/// @param end_len_strm the flag for end of message length input.
/// @param hash_strm the result.
/// @param end_hash_strm the flag for end of hash output.
template <int m_width>
void sha256(hls::stream<ap_uint<m_width> >& msg_strm,      // in
            hls::stream<ap_uint<64> >& len_strm,           // in
            hls::stream<bool>& end_len_strm,               // in
            hls::stream<ap_uint<256> >& hash_strm,         // out
            hls::stream<bool>& end_hash_strm) {            // out
    internal::sha256_top(msg_strm, len_strm, end_len_strm, // in
                         hash_strm, end_hash_strm);        // out
}
} // namespace security
} // namespace xf

// Clean up macros.
#undef ROTR
#undef ROTL
#undef SHR
#undef CH
#undef MAJ
#undef BSIG0
#undef BSIG1
#undef SSIG0
#undef SSIG1

#undef _XF_SECURITY_PRINT
#undef _XF_SECURITY_VOID_CAST

#endif // XF_SECURITY_SHA2_H
// -*- cpp -*-
// vim: ts=8:sw=2:sts=2:ft=cpp
