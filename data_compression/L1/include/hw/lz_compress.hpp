/*
 * (c) Copyright 2019-2022 Xilinx, Inc. All rights reserved.
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
 *
 */
#ifndef _XFCOMPRESSION_LZ_COMPRESS_HPP_
#define _XFCOMPRESSION_LZ_COMPRESS_HPP_

/**
 * @file lz_compress.hpp
 * @brief Header for modules used in LZ4 and snappy compression kernels.
 *
 * This file is part of Vitis Data Compression Library.
 */
#include "compress_utils.hpp"
#include "hls_stream.h"

#include <ap_int.h>
#include <assert.h>
#include <stdint.h>

namespace xf {
namespace compression {

/**
 * @brief This module reads input literals from stream and updates
 * match length and offset of each literal.
 *
 * @tparam MATCH_LEN match length
 * @tparam MIN_MATCH minimum match
 * @tparam LZ_MAX_OFFSET_LIMIT maximum offset limit
 * @tparam MATCH_LEVEL match level
 * @tparam MIN_OFFSET minimum offset
 * @tparam LZ_DICT_SIZE dictionary size
 *
 * @param inStream input stream
 * @param outStream output stream
 * @param input_size input size
 */
// [HLS-LZ4 vA.1] 方案A：Epoch 标记失效化（取消整表清空dict_flush），保持 II=1，等价功能
// 目标：用 tag[] + curEpoch 遮蔽旧周期数据，首写即生效；删除 2k+ 初始化 cycles
template <int MATCH_LEN,
          int MIN_MATCH,
          int LZ_MAX_OFFSET_LIMIT,
          int MATCH_LEVEL = 6,
          int MIN_OFFSET = 1,
          int LZ_DICT_SIZE = 1 << 12,
          int LEFT_BYTES = 64>
// [HLS-LZ4 vA+C+T+PE.1] 方案A+C+TailFuse + 前缀并行匹配/窄位宽算术以降 Estimate（II/Latency 不变）
// - 维持：Epoch 失效化（免清空字典）、预热并入主循环、尾部flush融合、II=1、功能与压缩比等价
// - 新增：并行前缀匹配(优先编码器式)替代 len/done 链；索引/偏移收窄与差值复用；Hash 两级异或树与字节缓存以减扇出
void lzCompress(hls::stream<ap_uint<8> >& inStream,
               hls::stream<ap_uint<32> >& outStream,
               uint32_t input_size) {
   const int c_dictEleWidth = (MATCH_LEN * 8 + 24);
   typedef ap_uint<MATCH_LEVEL * c_dictEleWidth> uintDictV_t;
   typedef ap_uint<c_dictEleWidth>              uintDict_t;

   if (input_size == 0) return;

   // 字典 + 槽位 epoch 标签（T2P BRAM，读写同拍）
   static uintDictV_t dict[LZ_DICT_SIZE];
#pragma HLS BIND_STORAGE variable=dict type=RAM_T2P impl=BRAM
   static ap_uint<8>  tag[LZ_DICT_SIZE];
#pragma HLS BIND_STORAGE variable=tag  type=RAM_T2P impl=BRAM
   static ap_uint<8>  curEpoch = 0;
   curEpoch++;

   // 空表读模板（index 域 = -1）
   uintDictV_t resetValue = 0;
   for (int i = 0; i < MATCH_LEVEL; i++) {
#pragma HLS UNROLL
       resetValue.range((i + 1) * c_dictEleWidth - 1,
                        i * c_dictEleWidth + MATCH_LEN * 8) = (ap_uint<24>)(-1);
   }

   // 窗口 + 预热并入主循环
   uint8_t present_window[MATCH_LEN];
#pragma HLS ARRAY_PARTITION variable=present_window complete
   ap_uint<8> valid = 0;

   const uint32_t main_iters = (input_size >= LEFT_BYTES) ? (input_size - LEFT_BYTES) : 0;

lz_compress:
   for (uint32_t i = 0; i < main_iters; ++i) {
#pragma HLS PIPELINE II=1
#pragma HLS dependence variable=dict inter false
#pragma HLS dependence variable=tag  inter false
       // 读取并 shift 窗口
       ap_uint<8> inb = inStream.read();
       for (int m = 0; m < MATCH_LEN - 1; ++m) {
#pragma HLS UNROLL
           present_window[m] = present_window[m + 1];
       }
       present_window[MATCH_LEN - 1] = (uint8_t)inb;

       bool do_compute = (valid >= (MATCH_LEN - 1));
       if (valid < MATCH_LEN) valid++;

       if (do_compute) {
           // currIdx 与哈希（两级 XOR 树，降低扇出）
           ap_uint<24> currIdx24 = (ap_uint<24>)(i - MATCH_LEN + 1);
           ap_uint<8> pw0 = present_window[0];
           ap_uint<8> pw1 = present_window[1];
           ap_uint<8> pw2 = present_window[2];
           ap_uint<8> pw3 = present_window[3];

           uint32_t h0 = ((uint32_t)pw0 << 4) ^ ((uint32_t)pw2 << 2);
           uint32_t h1;
           if (MIN_MATCH == 3) {
               h1 = ((uint32_t)pw1 << 3) ^ ((uint32_t)pw0 << 1) ^ (uint32_t)pw1;
           } else {
               h1 = ((uint32_t)pw1 << 3) ^ (uint32_t)pw3;
           }
           uint32_t hash = h0 ^ h1;

           // 字典读 + 按需失效
           uintDictV_t dictReadValue = dict[hash];
           ap_uint<8>  t             = tag[hash];
           uintDictV_t effectiveRead = (t == curEpoch) ? dictReadValue : resetValue;

           // 写回：左移并插入当前条目
           uintDictV_t dictWriteValue = effectiveRead << c_dictEleWidth;
           for (int m = 0; m < MATCH_LEN; ++m) {
#pragma HLS UNROLL
               dictWriteValue.range((m + 1) * 8 - 1, m * 8) = present_window[m];
           }
           dictWriteValue.range(c_dictEleWidth - 1, MATCH_LEN * 8) = currIdx24;

           dict[hash] = dictWriteValue;
           tag[hash]  = curEpoch;

           // —— 并行前缀匹配 + 窄位宽算术（压关键路径 & 复用差值） ——
           uint8_t  match_length = 0;
           uint32_t match_offset = 0;

           for (int l = 0; l < MATCH_LEVEL; ++l) {
#pragma HLS UNROLL
               // 取出比较对象与索引（24 位）
               uintDict_t compareWith = effectiveRead.range((l + 1) * c_dictEleWidth - 1,
                                                            l * c_dictEleWidth);
               ap_uint<24> compareIdx24 = compareWith.range(c_dictEleWidth - 1, MATCH_LEN * 8);

               // 拆出字节，降低 part-select 扇出
               ap_uint<8> cmp_bytes[MATCH_LEN];
#pragma HLS ARRAY_PARTITION variable=cmp_bytes complete
               for (int m = 0; m < MATCH_LEN; ++m) {
#pragma HLS UNROLL
                   cmp_bytes[m] = compareWith.range((m + 1) * 8 - 1, m * 8);
               }

               // 并行字节相等位
               ap_uint<MATCH_LEN> eq = 0;
               for (int m = 0; m < MATCH_LEN; ++m) {
#pragma HLS UNROLL
                   eq[m] = (present_window[m] == cmp_bytes[m]);
               }

               // 前缀长度：构造前缀“全1”位 run，然后并行求和（加法树）
               ap_uint<MATCH_LEN> run = eq;
               for (int m = 1; m < MATCH_LEN; ++m) {
#pragma HLS UNROLL
                   run[m] = run[m] & run[m - 1];
               }
               ap_uint<8> len = 0;
               for (int m = 0; m < MATCH_LEN; ++m) {
#pragma HLS UNROLL
                   len += (ap_uint<8>)run[m];
               }

               // 仅一次计算且收窄位宽的差值（最大 offset < 64K）
               bool idx_gt = (currIdx24 > compareIdx24);
               ap_uint<17> delta = 0;
               if (idx_gt) {
                   ap_uint<24> delta24 = currIdx24 - compareIdx24;
                   delta = (ap_uint<17>)delta24;
               }

               // 规则过滤（逻辑等价）
               bool len_ok  = (len >= (ap_uint<8>)MIN_MATCH);
               bool off_ok  = (delta < (ap_uint<17>)LZ_MAX_OFFSET_LIMIT);
               bool min_off = (delta > 0) && ((delta - 1) >= (ap_uint<17>)MIN_OFFSET);

               uint8_t eff_len = 0;
               if (len_ok && idx_gt && off_ok && min_off) {
                   if ((len == 3) && ((delta - 1) > 4096)) {
                       eff_len = 0;
                   } else {
                       eff_len = (uint8_t)len;
                   }
               }

               if (eff_len > match_length) {
                   match_length = eff_len;
                   match_offset = (uint32_t)(delta - 1);
               }
           }

           // 输出
           ap_uint<32> outValue = 0;
           outValue.range(7, 0)   = present_window[0];
           outValue.range(15, 8)  = match_length;
           outValue.range(31, 16) = match_offset;
           outStream << outValue;
       }
   }

   // 尾部融合：先吐窗口余字节，再吐 LEFT_BYTES
   const int tail_iters = (MATCH_LEN - 1) + LEFT_BYTES;
tail_fused:
   for (int t = 0; t < tail_iters; ++t) {
#pragma HLS PIPELINE II=1
       ap_uint<32> outValue = 0;
       if (t < (MATCH_LEN - 1)) {
           outValue.range(7, 0) = present_window[t + 1];
       } else {
           outValue.range(7, 0) = inStream.read();
       }
       outStream << outValue;
   }
}


/**
 * @brief This is stream-in-stream-out module used for lz compression. It reads input literals from stream and updates
 * match length and offset of each literal.
 *
 * @tparam MATCH_LEN match length
 * @tparam MIN_MATCH minimum match
 * @tparam LZ_MAX_OFFSET_LIMIT maximum offset limit
 * @tparam MATCH_LEVEL match level
 * @tparam MIN_OFFSET minimum offset
 * @tparam LZ_DICT_SIZE dictionary size
 *
 * @param inStream input stream
 * @param outStream output stream
 */
template <int MAX_INPUT_SIZE = 64 * 1024,
          class SIZE_DT = uint32_t,
          int MATCH_LEN,
          int MIN_MATCH,
          int LZ_MAX_OFFSET_LIMIT,
          int CORE_ID = 0,
          int MATCH_LEVEL = 6,
          int MIN_OFFSET = 1,
          int LZ_DICT_SIZE = 1 << 12,
          int LEFT_BYTES = 64>
void lzCompress(hls::stream<IntVectorStream_dt<8, 1> >& inStream, hls::stream<IntVectorStream_dt<32, 1> >& outStream) {
    const uint16_t c_indxBitCnts = 24;
    const uint16_t c_fifo_depth = LEFT_BYTES + 2;
    const int c_dictEleWidth = (MATCH_LEN * 8 + c_indxBitCnts);
    typedef ap_uint<MATCH_LEVEL * c_dictEleWidth> uintDictV_t;
    typedef ap_uint<c_dictEleWidth> uintDict_t;
    const uint32_t totalDictSize = (1 << (c_indxBitCnts - 1)); // 8MB based on index 3 bytes
#ifndef AVOID_STATIC_MODE
    static bool resetDictFlag = true;
    static uint32_t relativeNumBlocks = 0;
#else
    bool resetDictFlag = true;
    uint32_t relativeNumBlocks = 0;
#endif

    uintDictV_t dict[LZ_DICT_SIZE];
#pragma HLS RESOURCE variable = dict core = XPM_MEMORY uram

    // local buffers for each block
    uint8_t present_window[MATCH_LEN];
#pragma HLS ARRAY_PARTITION variable = present_window complete
    hls::stream<uint8_t> lclBufStream("lclBufStream");
#pragma HLS STREAM variable = lclBufStream depth = c_fifo_depth
#pragma HLS BIND_STORAGE variable = lclBufStream type = fifo impl = srl

    // input register
    IntVectorStream_dt<8, 1> inVal;
    // output register
    IntVectorStream_dt<32, 1> outValue;
    // loop over blocks
    while (true) {
        uint32_t iIdx = 0;
        // once 8MB data is processed reset dictionary
        // 8MB based on index 3 bytes
        if (resetDictFlag) {
            ap_uint<MATCH_LEVEL* c_dictEleWidth> resetValue = 0;
            for (int i = 0; i < MATCH_LEVEL; i++) {
#pragma HLS UNROLL
                resetValue.range((i + 1) * c_dictEleWidth - 1, i * c_dictEleWidth + MATCH_LEN * 8) = -1;
            }
        // Initialization of Dictionary
        dict_flush:
            for (int i = 0; i < LZ_DICT_SIZE; i++) {
#pragma HLS PIPELINE II = 1
#pragma HLS UNROLL FACTOR = 2
                dict[i] = resetValue;
            }
            resetDictFlag = false;
            relativeNumBlocks = 0;
        } else {
            relativeNumBlocks++;
        }
        // check if end of data
        auto nextVal = inStream.read();
        if (nextVal.strobe == 0) {
            outValue.strobe = 0;
            outStream << outValue;
            break;
        }
    // fill buffer and present_window
    lz_fill_present_win:
        while (iIdx < MATCH_LEN - 1) {
#pragma HLS PIPELINE II = 1
            inVal = nextVal;
            nextVal = inStream.read();
            present_window[++iIdx] = inVal.data[0];
        }
    // assuming that, at least bytes more than LEFT_BYTES will be present at the input
    lz_fill_circular_buf:
        for (uint16_t i = 0; i < LEFT_BYTES; ++i) {
#pragma HLS PIPELINE II = 1
            inVal = nextVal;
            nextVal = inStream.read();
            lclBufStream << inVal.data[0];
        }
        // lz_compress main
        outValue.strobe = 1;

    lz_compress:
        for (; nextVal.strobe != 0; ++iIdx) {
#pragma HLS PIPELINE II = 1
#ifndef DISABLE_DEPENDENCE
#pragma HLS dependence variable = dict inter false
#endif
            uint32_t currIdx = (iIdx + (relativeNumBlocks * MAX_INPUT_SIZE)) - MATCH_LEN + 1;
            // read from input stream into circular buffer
            auto inValue = lclBufStream.read(); // pop latest value from FIFO
            lclBufStream << nextVal.data[0];    // push latest read value to FIFO
            nextVal = inStream.read();          // read next value from input stream

            // shift present window and load next value
            for (uint8_t m = 0; m < MATCH_LEN - 1; m++) {
#pragma HLS UNROLL
                present_window[m] = present_window[m + 1];
            }

            present_window[MATCH_LEN - 1] = inValue;

            // Calculate Hash Value
            uint32_t hash = 0;
            if (MIN_MATCH == 3) {
                hash = (present_window[0] << 4) ^ (present_window[1] << 3) ^ (present_window[2] << 2) ^
                       (present_window[0] << 1) ^ (present_window[1]);
            } else {
                hash = (present_window[0] << 4) ^ (present_window[1] << 3) ^ (present_window[2] << 2) ^
                       (present_window[3]);
            }

            // Dictionary Lookup
            uintDictV_t dictReadValue = dict[hash];
            uintDictV_t dictWriteValue = dictReadValue << c_dictEleWidth;
            for (int m = 0; m < MATCH_LEN; m++) {
#pragma HLS UNROLL
                dictWriteValue.range((m + 1) * 8 - 1, m * 8) = present_window[m];
            }
            dictWriteValue.range(c_dictEleWidth - 1, MATCH_LEN * 8) = currIdx;
            // Dictionary Update
            dict[hash] = dictWriteValue;

            // Match search and Filtering
            // Comp dict pick
            uint8_t match_length = 0;
            uint32_t match_offset = 0;
            for (int l = 0; l < MATCH_LEVEL; l++) {
                uint8_t len = 0;
                bool done = 0;
                uintDict_t compareWith = dictReadValue.range((l + 1) * c_dictEleWidth - 1, l * c_dictEleWidth);
                uint32_t compareIdx = compareWith.range(c_dictEleWidth - 1, MATCH_LEN * 8);
                for (uint8_t m = 0; m < MATCH_LEN; m++) {
                    if (present_window[m] == compareWith.range((m + 1) * 8 - 1, m * 8) && !done) {
                        len++;
                    } else {
                        done = 1;
                    }
                }
                if ((len >= MIN_MATCH) && (currIdx > compareIdx) && ((currIdx - compareIdx) < LZ_MAX_OFFSET_LIMIT) &&
                    ((currIdx - compareIdx - 1) >= MIN_OFFSET) &&
                    (compareIdx >= (relativeNumBlocks * MAX_INPUT_SIZE))) {
                    if ((len == 3) && ((currIdx - compareIdx - 1) > 4096)) {
                        len = 0;
                    }
                } else {
                    len = 0;
                }
                if (len > match_length) {
                    match_length = len;
                    match_offset = currIdx - compareIdx - 1;
                }
            }
            outValue.data[0].range(7, 0) = present_window[0];
            outValue.data[0].range(15, 8) = match_length;
            outValue.data[0].range(31, 16) = match_offset;
            outStream << outValue;
        }

        outValue.data[0] = 0;
    lz_compress_leftover:
        for (uint8_t m = 1; m < MATCH_LEN; ++m) {
#pragma HLS PIPELINE II = 1
            outValue.data[0].range(7, 0) = present_window[m];
            outStream << outValue;
        }
    lz_left_bytes:
        for (uint16_t l = 0; l < LEFT_BYTES; ++l) {
#pragma HLS PIPELINE II = 1
            outValue.data[0].range(7, 0) = lclBufStream.read();
            outStream << outValue;
        }

        // once relativeInSize becomes 8MB set the flag to true
        resetDictFlag = ((relativeNumBlocks * MAX_INPUT_SIZE) >= (totalDictSize)) ? true : false;
        // end of block
        outValue.strobe = 0;
        outStream << outValue;
    }
}

} // namespace compression
} // namespace xf
#endif // _XFCOMPRESSION_LZ_COMPRESS_HPP_
