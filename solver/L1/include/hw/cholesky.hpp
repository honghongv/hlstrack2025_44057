/*
 * Copyright 2021 Xilinx, Inc.
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

/**
 * @file cholesky.hpp
 * @brief This file contains cholesky functions
 *   - cholesky                 : Entry point function
 *   - choleskyTop             : Top level function that selects implementation architecture and internal types based
 * on a traits class.
 *   - choleskyBasic           : Basic implementation requiring lower resource
 *   - choleskyAlt             : Lower latency architecture requiring more resources
 *   - choleskyAlt2            : Further improved latency architecture requiring higher resource
 */

#ifndef _XF_SOLVER_CHOLESKY_HPP_
#define _XF_SOLVER_CHOLESKY_HPP_

#include "ap_fixed.h"
#include "hls_x_complex.h"
#include <complex>
#include "utils/std_complex_utils.h"
#include "utils/x_matrix_utils.hpp"
#include "hls_stream.h"

namespace xf {
namespace solver {

// ===================================================================================================================
// Default traits struct defining the internal variable types for the cholesky function
template <bool LowerTriangularL, int RowsColsA, typename InputType, typename OutputType>
struct choleskyTraits {
    typedef InputType PROD_T;
    typedef InputType ACCUM_T;
    typedef InputType ADD_T;
    typedef InputType DIAG_T;
    typedef InputType RECIP_DIAG_T;
    typedef InputType OFF_DIAG_T;
    typedef OutputType L_OUTPUT_T;
    static const int ARCH =
        1; // Select implementation: 0=Basic, 1=Lower latency architecture, 2=Further improved latency architecture
    static const int INNER_II = 1; // Specify the pipelining target for the inner loop
    static const int UNROLL_FACTOR =
        1; // Specify the inner loop unrolling factor for the choleskyAlt2 architecture(2) to increase throughput
    static const int UNROLL_DIM = (LowerTriangularL == true ? 1 : 2); // Dimension to unroll matrix
    static const int ARCH2_ZERO_LOOP =
        true; // Additional implementation "switch" for the choleskyAlt2 architecture (2).
};

// Specialization for complex
template <bool LowerTriangularL, int RowsColsA, typename InputBaseType, typename OutputBaseType>
struct choleskyTraits<LowerTriangularL, RowsColsA, hls::x_complex<InputBaseType>, hls::x_complex<OutputBaseType> > {
    typedef hls::x_complex<InputBaseType> PROD_T;
    typedef hls::x_complex<InputBaseType> ACCUM_T;
    typedef hls::x_complex<InputBaseType> ADD_T;
    typedef hls::x_complex<InputBaseType> DIAG_T;
    typedef InputBaseType RECIP_DIAG_T;
    typedef hls::x_complex<InputBaseType> OFF_DIAG_T;
    typedef hls::x_complex<OutputBaseType> L_OUTPUT_T;
    static const int ARCH = 1;
    static const int INNER_II = 1;
    static const int UNROLL_FACTOR = 1;
    static const int UNROLL_DIM = (LowerTriangularL == true ? 1 : 2);
    static const int ARCH2_ZERO_LOOP = true;
};

// Specialization for std complex
template <bool LowerTriangularL, int RowsColsA, typename InputBaseType, typename OutputBaseType>
struct choleskyTraits<LowerTriangularL, RowsColsA, std::complex<InputBaseType>, std::complex<OutputBaseType> > {
    typedef std::complex<InputBaseType> PROD_T;
    typedef std::complex<InputBaseType> ACCUM_T;
    typedef std::complex<InputBaseType> ADD_T;
    typedef std::complex<InputBaseType> DIAG_T;
    typedef InputBaseType RECIP_DIAG_T;
    typedef std::complex<InputBaseType> OFF_DIAG_T;
    typedef std::complex<OutputBaseType> L_OUTPUT_T;
    static const int ARCH = 1;
    static const int INNER_II = 1;
    static const int UNROLL_FACTOR = 1;
    static const int UNROLL_DIM = (LowerTriangularL == true ? 1 : 2);
    static const int ARCH2_ZERO_LOOP = true;
};

// Specialization for ap_fixed
template <bool LowerTriangularL,
          int RowsColsA,
          int W1,
          int I1,
          ap_q_mode Q1,
          ap_o_mode O1,
          int N1,
          int W2,
          int I2,
          ap_q_mode Q2,
          ap_o_mode O2,
          int N2>
struct choleskyTraits<LowerTriangularL, RowsColsA, ap_fixed<W1, I1, Q1, O1, N1>, ap_fixed<W2, I2, Q2, O2, N2> > {
    typedef ap_fixed<W1 + W1, I1 + I1, AP_RND_CONV, AP_SAT, 0> PROD_T;
    typedef ap_fixed<(W1 + W1) + BitWidth<RowsColsA>::Value,
                     (I1 + I1) + BitWidth<RowsColsA>::Value,
                     AP_RND_CONV,
                     AP_SAT,
                     0>
        ACCUM_T;
    typedef ap_fixed<W1 + 1, I1 + 1, AP_RND_CONV, AP_SAT, 0> ADD_T;
    typedef ap_fixed<(W1 + 1) * 2, I1 + 1, AP_RND_CONV, AP_SAT, 0> DIAG_T;     // Takes result of sqrt
    typedef ap_fixed<(W1 + 1) * 2, I1 + 1, AP_RND_CONV, AP_SAT, 0> OFF_DIAG_T; // Takes result of /
    typedef ap_fixed<2 + (W2 - I2) + W2, 2 + (W2 - I2), AP_RND_CONV, AP_SAT, 0> RECIP_DIAG_T;
    typedef ap_fixed<W2, I2, AP_RND_CONV, AP_SAT, 0>
        L_OUTPUT_T; // Takes new L value.  Same as L output but saturation set
    static const int ARCH = 1;
    static const int INNER_II = 1;
    static const int UNROLL_FACTOR = 1;
    static const int UNROLL_DIM = (LowerTriangularL == true ? 1 : 2);
    static const int ARCH2_ZERO_LOOP = true;
};

// Further specialization for hls::complex<ap_fixed>
template <bool LowerTriangularL,
          int RowsColsA,
          int W1,
          int I1,
          ap_q_mode Q1,
          ap_o_mode O1,
          int N1,
          int W2,
          int I2,
          ap_q_mode Q2,
          ap_o_mode O2,
          int N2>
struct choleskyTraits<LowerTriangularL,
                      RowsColsA,
                      hls::x_complex<ap_fixed<W1, I1, Q1, O1, N1> >,
                      hls::x_complex<ap_fixed<W2, I2, Q2, O2, N2> > > {
    typedef hls::x_complex<ap_fixed<W1 + W1, I1 + I1, AP_RND_CONV, AP_SAT, 0> > PROD_T;
    typedef hls::x_complex<ap_fixed<(W1 + W1) + BitWidth<RowsColsA>::Value,
                                    (I1 + I1) + BitWidth<RowsColsA>::Value,
                                    AP_RND_CONV,
                                    AP_SAT,
                                    0> >
        ACCUM_T;
    typedef hls::x_complex<ap_fixed<W1 + 1, I1 + 1, AP_RND_CONV, AP_SAT, 0> > ADD_T;
    typedef hls::x_complex<ap_fixed<(W1 + 1) * 2, I1 + 1, AP_RND_CONV, AP_SAT, 0> > DIAG_T;     // Takes result of sqrt
    typedef hls::x_complex<ap_fixed<(W1 + 1) * 2, I1 + 1, AP_RND_CONV, AP_SAT, 0> > OFF_DIAG_T; // Takes result of /
    typedef ap_fixed<2 + (W2 - I2) + W2, 2 + (W2 - I2), AP_RND_CONV, AP_SAT, 0> RECIP_DIAG_T;
    typedef hls::x_complex<ap_fixed<W2, I2, AP_RND_CONV, AP_SAT, 0> >
        L_OUTPUT_T; // Takes new L value.  Same as L output but saturation set
    static const int ARCH = 1;
    static const int INNER_II = 1;
    static const int UNROLL_FACTOR = 1;
    static const int UNROLL_DIM = (LowerTriangularL == true ? 1 : 2);
    static const int ARCH2_ZERO_LOOP = true;
};

// Further specialization for std::complex<ap_fixed>
template <bool LowerTriangularL,
          int RowsColsA,
          int W1,
          int I1,
          ap_q_mode Q1,
          ap_o_mode O1,
          int N1,
          int W2,
          int I2,
          ap_q_mode Q2,
          ap_o_mode O2,
          int N2>
struct choleskyTraits<LowerTriangularL,
                      RowsColsA,
                      std::complex<ap_fixed<W1, I1, Q1, O1, N1> >,
                      std::complex<ap_fixed<W2, I2, Q2, O2, N2> > > {
    typedef std::complex<ap_fixed<W1 + W1, I1 + I1, AP_RND_CONV, AP_SAT, 0> > PROD_T;
    typedef std::complex<ap_fixed<(W1 + W1) + BitWidth<RowsColsA>::Value,
                                  (I1 + I1) + BitWidth<RowsColsA>::Value,
                                  AP_RND_CONV,
                                  AP_SAT,
                                  0> >
        ACCUM_T;
    typedef std::complex<ap_fixed<W1 + 1, I1 + 1, AP_RND_CONV, AP_SAT, 0> > ADD_T;
    typedef std::complex<ap_fixed<(W1 + 1) * 2, I1 + 1, AP_RND_CONV, AP_SAT, 0> > DIAG_T;     // Takes result of sqrt
    typedef std::complex<ap_fixed<(W1 + 1) * 2, I1 + 1, AP_RND_CONV, AP_SAT, 0> > OFF_DIAG_T; // Takes result of /
    typedef ap_fixed<2 + (W2 - I2) + W2, 2 + (W2 - I2), AP_RND_CONV, AP_SAT, 0> RECIP_DIAG_T;
    typedef std::complex<ap_fixed<W2, I2, AP_RND_CONV, AP_SAT, 0> >
        L_OUTPUT_T; // Takes new L value.  Same as L output but saturation set
    static const int ARCH = 1;
    static const int INNER_II = 1;
    static const int UNROLL_FACTOR = 1;
    static const int UNROLL_DIM = (LowerTriangularL == true ? 1 : 2);
    static const int ARCH2_ZERO_LOOP = true;
};

// ===================================================================================================================
// Helper functions

// Square root
// o Overloaded versions of the sqrt function
// o The square root of a complex number is expensive.  However, the diagonal values of a Cholesky decomposition are
// always
//   real so we don't need a full complex square root.
template <typename T_IN, typename T_OUT>
int cholesky_sqrt_op(T_IN a, T_OUT& b) {
Function_cholesky_sqrt_op_real:;
    const T_IN ZERO = 0;
    if (a < ZERO) {
        b = ZERO;
        return (1);
    }
    b = x_sqrt(a);
    return (0);
}
template <typename T_IN, typename T_OUT>
int cholesky_sqrt_op(hls::x_complex<T_IN> din, hls::x_complex<T_OUT>& dout) {
Function_cholesky_sqrt_op_complex:;
    const T_IN ZERO = 0;
    T_IN a = din.real();
    dout.imag(ZERO);

    if (a < ZERO) {
        dout.real(ZERO);
        return (1);
    }

    dout.real(x_sqrt(a));
    return (0);
}
template <typename T_IN, typename T_OUT>
int cholesky_sqrt_op(std::complex<T_IN> din, std::complex<T_OUT>& dout) {
Function_cholesky_sqrt_op_complex:;
    const T_IN ZERO = 0;
    T_IN a = din.real();
    dout.imag(ZERO);

    if (a < ZERO) {
        dout.real(ZERO);
        return (1);
    }

    dout.real(x_sqrt(a));
    return (0);
}

// Reciprocal square root.
// ============================================================================
// [版本] cholesky_rsqrt v2.1
// [说明] 统一走“1/√x”快速路径：
//  - 泛型：直接调用 x_rsqrt ，流水 II=1；
//  - ap_fixed 特化：先用 float 的 x_rsqrt 得到初值，再在 fixed 域做 1 次牛顿迭代，
//    y_{n+1} = y_n * (1.5 - 0.5 * x * y_n^2)，去掉昂贵的 sqrt & divide。
//    中间计算用加宽定点，全部流水化，II=1，避免长组合链。
// ============================================================================

template <typename InputType, typename OutputType>
void cholesky_rsqrt(InputType x, OutputType& res) {
#pragma HLS INLINE
#pragma HLS PIPELINE II=1
    // 对于浮点或已支持的类型，直接走 x_rsqrt
    res = (OutputType)x_rsqrt(x);
}

// 固定点专用特化：去掉 sqrt + 1/div，改为 rsqrt + 1 次牛顿迭代（II=1）
template <int W1, int I1, ap_q_mode Q1, ap_o_mode O1, int N1,
          int W2, int I2, ap_q_mode Q2, ap_o_mode O2, int N2>
void cholesky_rsqrt(ap_fixed<W1, I1, Q1, O1, N1> x,
                    ap_fixed<W2, I2, Q2, O2, N2>& res) {
#pragma HLS INLINE off
#pragma HLS PIPELINE II=1

    // ---- 保护 & 扩宽类型 ----
    // 运行中 x 已在 choleskyAlt 中检查为正；这里作最小保护，避免非常小值数值不稳。
    typedef ap_fixed<( (W1>W2)?W1:W2 ) + 8, ( (I1>I2)?I1:I2 ) + 4, AP_TRN, AP_WRAP, 0> work_t;
    work_t xin = (x <= 0) ? (work_t)1 : (work_t)x;

    // ---- 初值：用 float 的快速 rsqrt 近似（延时短、吞吐高）----
    float xf  = (float)xin;
    float y0f = x_rsqrt(xf);                // 初值
    work_t y  = (work_t)y0f;                // 回到定点域

    // ---- 1 次牛顿迭代（定点域），II=1 流水；不形成长链 ----
    // y = y * (1.5 - 0.5*x*y*y)
    work_t half   = (work_t)0.5;
    work_t onept5 = (work_t)1.5;

    // 适配 DSP，防止资源共享导致 II>1
#pragma HLS BIND_OP variable=y    op=mul impl=DSP
#pragma HLS BIND_OP variable=half op=mul impl=Auto

    work_t y_sq   = y * y;                  // 1
    work_t term   = onept5 - half * xin * y_sq; // 2（两次乘法会被排布到流水）
    y             = y * term;               // 3

    // ---- 截断/舍入到目标格式 ----
    res = (ap_fixed<W2, I2, Q2, O2, N2>)y;
}


// ============================================================================
// [版本] vPSM-2.0  —— 乘法内联加速（II=1，DSP 绑定，复数双乘并行）
// [说明]
// - 目的：把原先 4-cycle 的专用模块收编为内联运算，减少函数级延迟与调度开销；确保外层循环仍可 II=1。
// - 做法：所有分支均使用 `#pragma HLS INLINE` + `#pragma HLS PIPELINE II=1`；
//         对乘法操作绑定到 DSP（不共享），复数分支同时计算实部/虚部两路乘法。
// - 数值等价：保持与原实现相同的数值路径（实/复 与实数相乘），最终写回时转换为目标 CType。
// - 适用：ap_fixed / float / double / hls::x_complex / std::complex 等常见类型组合。
// ============================================================================

// 实数（或标量）× 实数（或标量） → 标量
template <typename AType, typename BType, typename CType>
void cholesky_prod_sum_mult(AType A, BType B, CType& C) {
#pragma HLS INLINE

// 绑定乘法到 DSP，避免资源共享导致的 II 抖动
#pragma HLS BIND_OP op=mul impl=DSP
    C = (CType)(A * B);
}

// 复数（hls::x_complex）× 实数 → 复数（逐分量缩放）
template <typename AType, typename BType, typename CType>
void cholesky_prod_sum_mult(hls::x_complex<AType> A, BType B, hls::x_complex<CType>& C) {
#pragma HLS INLINE

    // 两路乘法可并行调度到两个 DSP
    auto r = A.real() * B;
#pragma HLS BIND_OP variable=r op=mul impl=DSP
    auto i = A.imag() * B;
#pragma HLS BIND_OP variable=i op=mul impl=DSP
    C.real((CType)r);
    C.imag((CType)i);
}

// 复数（std::complex）× 实数 → 复数（逐分量缩放）
template <typename AType, typename BType, typename CType>
void cholesky_prod_sum_mult(std::complex<AType> A, BType B, std::complex<CType>& C) {
#pragma HLS INLINE

    auto r = A.real() * B;
#pragma HLS BIND_OP variable=r op=mul impl=DSP
    auto i = A.imag() * B;
#pragma HLS BIND_OP variable=i op=mul impl=DSP
    C.real((CType)r);
    C.imag((CType)i);
}


// ===================================================================================================================
// choleskyBasic
template <bool LowerTriangularL, int RowsColsA, typename CholeskyTraits, class InputType, class OutputType>
int choleskyBasic(const InputType A[RowsColsA][RowsColsA], OutputType L[RowsColsA][RowsColsA]) {
    int return_code = 0;

    // Use the traits struct to specify the correct type for the intermediate variables. This is really only needed for
    // fixed point.
    typename CholeskyTraits::PROD_T prod;
    typename CholeskyTraits::ACCUM_T sum[RowsColsA];
    typename CholeskyTraits::ACCUM_T A_cast_to_sum;    // A with the same dimensions as sum.
    typename CholeskyTraits::ACCUM_T prod_cast_to_sum; // prod with the same dimensions as sum.

    typename CholeskyTraits::ADD_T A_minus_sum;
    typename CholeskyTraits::DIAG_T new_L_diag;         // sqrt(A_minus_sum)
    typename CholeskyTraits::OFF_DIAG_T new_L_off_diag; // sum/L
    typename CholeskyTraits::OFF_DIAG_T L_cast_to_new_L_off_diag;

    typename CholeskyTraits::L_OUTPUT_T new_L;
    OutputType retrieved_L;
    // Internal memory used to aviod read access from function output argument L.
    // NOTE: The internal matrix only needs to be triangular but optimization using a 1-D array it will require addition
    // logic to generate the indexes. Refer to the choleskyAlt function.
    OutputType L_internal[RowsColsA][RowsColsA];

col_loop:
    for (int j = 0; j < RowsColsA; j++) {
        sum[j] = 0;

    // Calculate the diagonal value for this column
    diag_loop:
        for (int k = 0; k < RowsColsA; k++) {
            if (k <= (j - 1)) {
                if (LowerTriangularL == true) {
                    retrieved_L = L_internal[j][k];
                } else {
                    retrieved_L = L_internal[k][j];
                }
                sum[j] = hls::x_conj(retrieved_L) * retrieved_L;
            }
        }
        A_cast_to_sum = A[j][j];

        A_minus_sum = A_cast_to_sum - sum[j];

        if (cholesky_sqrt_op(A_minus_sum, new_L_diag)) {
#ifndef __SYNTHESIS__
            printf("ERROR: Trying to find the square root of a negative number\n");
#endif
            return_code = 1;
        }

        // Round to target format using method specifed by traits defined types.
        new_L = new_L_diag;

        if (LowerTriangularL == true) {
            L_internal[j][j] = new_L;
            L[j][j] = new_L;
        } else {
            L_internal[j][j] = hls::x_conj(new_L);
            L[j][j] = hls::x_conj(new_L);
        }

    // Calculate the off diagonal values for this column
    off_diag_loop:
        for (int i = 0; i < RowsColsA; i++) {
            if (i > j) {
                if (LowerTriangularL == true) {
                    sum[j] = A[i][j];
                } else {
                    sum[j] = hls::x_conj(A[j][i]);
                }

            sum_loop:
                for (int k = 0; k < RowsColsA; k++) {
#pragma HLS PIPELINE II = CholeskyTraits::INNER_II
                    if (k <= (j - 1)) {
                        if (LowerTriangularL == true) {
                            prod = -L_internal[i][k] * hls::x_conj(L_internal[j][k]);
                        } else {
                            prod = -hls::x_conj(L_internal[k][i]) * (L_internal[k][j]);
                        }

                        prod_cast_to_sum = prod;
                        sum[j] += prod_cast_to_sum;
                    }
                }

                new_L_off_diag = sum[j];

                L_cast_to_new_L_off_diag = L_internal[j][j];

                // Diagonal is always real, avoid complex division
                new_L_off_diag = new_L_off_diag / hls::x_real(L_cast_to_new_L_off_diag);

                // Round to target format using method specifed by traits defined types.
                new_L = new_L_off_diag;

                if (LowerTriangularL == true) {
                    L[i][j] = new_L;
                    L_internal[i][j] = new_L;
                } else {
                    L[j][i] = hls::x_conj(new_L);
                    L_internal[j][i] = hls::x_conj(new_L);
                }
            } else if (i < j) {
                if (LowerTriangularL == true) {
                    L[i][j] = 0;
                } else {
                    L[j][i] = 0;
                }
            }
        }
    }
    return (return_code);
}


// ===================================================================================================================
// [版本] vA-2.2-Fmax-fix —— 小矩阵寄存器Bank + 复数3乘法(降低组合深度) + 对角mag²显式分解
// [要点]
// 1) RowsColsA ≤ 8：用全寄存器 L_bank 完全分区，列内 P_PAR×UF 并行且 II=1；
// 2) 列级预取并预计算 L(j,k) 的实部/虚部/(c-d)，内环用 3 乘法公式：m1=a*c, m2=b*d, m3=(a+b)*(c-d)；
//    对角平方和用 |v|² = vr*vr + vi*vi，减轻组合深度，有利于降低 Estimated；
// 3) RowsColsA > 8：保持你现有的大矩阵（多副本）路径不变；
// 4) 不修改 cholesky_rsqrt / cholesky_prod_sum_mult 的现有加速实现。
// ===================================================================================================================
template <bool LowerTriangularL, int RowsColsA, typename CholeskyTraits, class InputType, class OutputType>
int choleskyAlt(const InputType A[RowsColsA][RowsColsA], OutputType L[RowsColsA][RowsColsA]) {
#pragma HLS INLINE off

    // -----------------------------
    // 通用类型别名
    // -----------------------------
    typedef typename CholeskyTraits::ACCUM_T       ACC_T;
    typedef typename CholeskyTraits::ADD_T         ADD_T;
    typedef typename CholeskyTraits::DIAG_T        DIAG_T;
    typedef typename CholeskyTraits::RECIP_DIAG_T  RDIAG_T;
    typedef typename CholeskyTraits::OFF_DIAG_T    OFF_T;
    typedef typename CholeskyTraits::L_OUTPUT_T    LOUT_T;
    typedef typename CholeskyTraits::PROD_T        PROD_T;

    // 小矩阵并行参数
    static const int P_PAR = (RowsColsA <= 8) ? 2 : 8;
    static const int UF    = (RowsColsA <= 8) ? 2 : 4;

    // 列广播缓冲与锚
    LOUT_T rowj[RowsColsA];
#pragma HLS ARRAY_PARTITION variable=rowj complete
    ACC_T  anchor[RowsColsA];
#pragma HLS ARRAY_PARTITION variable=anchor complete

    // 用 decltype 推导标量类型（兼容实数/复数/定点）
    typedef decltype(hls::x_real(LOUT_T())) SCALAR_T;
    typedef decltype(hls::x_real(ACC_T()))  ACC_SCALAR_T;
    typedef decltype(hls::x_real(OFF_T()))  OFF_SCALAR_T;

    // 预计算分量
    SCALAR_T rowj_r[RowsColsA];         // Re{L(j,k)}
    SCALAR_T rowj_i[RowsColsA];         // Im{L(j,k)}
    SCALAR_T rowj_r_minus_i[RowsColsA]; // (c - d)
#pragma HLS ARRAY_PARTITION variable=rowj_r complete
#pragma HLS ARRAY_PARTITION variable=rowj_i complete
#pragma HLS ARRAY_PARTITION variable=rowj_r_minus_i complete

    // 对角缓存
    static RDIAG_T diag_recip[RowsColsA];
    static LOUT_T  diag_out  [RowsColsA];
#pragma HLS ARRAY_PARTITION variable=diag_recip complete

    // 操作符并行：避免资源共享拖慢 II
#pragma HLS ALLOCATION instances=mul limit=-1 operation
#pragma HLS ALLOCATION instances=add limit=-1 operation

    int return_code = 0;

    // 行偏移（大矩阵路径会用到）
    auto row_off = [](int idx)->int {
        int s = idx - 1;
        return ((s * s - s) / 2) + s; // == idx*(idx-1)/2
    };

    // -----------------------------
    // Small-N 寄存器Bank路径（RowsColsA ≤ 8）
    // -----------------------------
    if (RowsColsA <= 8) {
        LOUT_T L_bank[RowsColsA][RowsColsA];
#pragma HLS ARRAY_PARTITION variable=L_bank dim=1 complete
#pragma HLS ARRAY_PARTITION variable=L_bank dim=2 complete

    col_loop_small:
        for (int j = 0; j < RowsColsA; ++j) {

        // 0) 预取 A 的锚值
        prefetch_anchor_small:
            for (int i = j; i < RowsColsA; ++i) {
#pragma HLS PIPELINE II=1
                anchor[i] = LowerTriangularL ? (ACC_T)A[i][j]
                                             : (ACC_T)hls::x_conj(A[j][i]);
            }

            // 1) 对角：diff = A[j][j] - Σ_k |L(j,k)|^2
            ACC_T squares = ACC_T(); // 0
            if (j > 0) {
            sum_j_loop_small:
                for (int k = 0; k < j; ++k) {
#pragma HLS PIPELINE II=1
                    LOUT_T v = L_bank[j][k];
                    rowj[k]  = v;
                    // 预计算分量与 (c - d)
                    SCALAR_T vr = hls::x_real(v);
                    SCALAR_T vi = hls::x_imag(v);
                    rowj_r[k]         = vr;
                    rowj_i[k]         = vi;
                    rowj_r_minus_i[k] = vr - vi;
                    // |v|^2 = vr*vr + vi*vi
                    squares += (ACC_T)(vr * vr + vi * vi);
                }
            }
            ACC_T aii = (ACC_T)A[j][j];
            ADD_T diff = (ADD_T)(aii - squares);

            auto x_real = hls::x_real((DIAG_T)diff);
            if (x_real <= 0) {
#ifndef __SYNTHESIS__
                printf("ERROR: Trying to find the square root of a negative number\n");
#endif
                return_code = 1;
            }

            // rsqrt 融合
            RDIAG_T rcp_sqrt;
#pragma HLS PIPELINE II=1
            cholesky_rsqrt(x_real, rcp_sqrt);
            diag_recip[j] = rcp_sqrt;

            DIAG_T Ljj_diag = (DIAG_T)(x_real * rcp_sqrt);
            LOUT_T Ljj_out  = (LOUT_T)Ljj_diag;
            diag_out[j]     = Ljj_out;

            if (LowerTriangularL) {
                L[j][j] = (OutputType)Ljj_out;
            } else {
                L[j][j] = (OutputType)hls::x_conj(Ljj_out);
            }

            // 2) 列内并行：i=j+1..N-1（复数3乘法以降组合深度）
            if (j < RowsColsA - 1) {
            i_batch_loop_small:
                for (int base = j + 1; base < RowsColsA; base += P_PAR) {
                pe_loop_small:
                    for (int p = 0; p < P_PAR; ++p) {
#pragma HLS UNROLL
                        const int i = base + p;
                        if (i < RowsColsA) {

                            ACC_SCALAR_T acc_r = hls::x_real(anchor[i]);
                            ACC_SCALAR_T acc_i = hls::x_imag(anchor[i]);

                        t_loop_small:
                            for (int t = 0; t < j; t += UF) {
#pragma HLS PIPELINE II=1
                            u_loop_small:
                                for (int u = 0; u < UF; ++u) {
#pragma HLS UNROLL
                                    const int k = t + u;
                                    if (k < j) {
                                        // li = a+bi, conj(lj)=c - di；3乘法
                                        LOUT_T   li = L_bank[i][k];
                                        SCALAR_T a  = hls::x_real(li);
                                        SCALAR_T b  = hls::x_imag(li);
                                        SCALAR_T c  = rowj_r[k];
                                        SCALAR_T d  = rowj_i[k];
                                        SCALAR_T cd = rowj_r_minus_i[k];

                                        SCALAR_T m1  = a * c;
                                        SCALAR_T m2  = b * d;
                                        SCALAR_T apb = a + b;
                                        SCALAR_T m3  = apb * cd;

                                        SCALAR_T t_real = m1 + m2;
                                        SCALAR_T t_imag = (m3 - m1) + m2;

                                        acc_r -= t_real;
                                        acc_i -= t_imag;
                                    }
                                }
                            } // t_loop_small

                            // 拼回 OFF_T 再与 diag_recip 相乘
                            OFF_T sum_off;
                            // 这里假定 OFF_T 为复数类型（与当前工程一致）；若为实数则仅置 real
                            sum_off.real((OFF_SCALAR_T)acc_r);
                            sum_off.imag((OFF_SCALAR_T)acc_i);

                            OFF_T lij;
                            cholesky_prod_sum_mult(sum_off, diag_recip[j], lij);

                            L_bank[i][j] = (LOUT_T)lij;

                            if (LowerTriangularL) {
                                L[i][j] = (OutputType)lij;
                                L[j][i] = (OutputType)0;
                            } else {
                                L[j][i] = (OutputType)hls::x_conj(lij);
                                L[i][j] = (OutputType)0;
                            }
                        }
                    }
                }
            }
        } // col_loop_small

        return return_code;
    }

    // -----------------------------
    // 大矩阵（RowsColsA > 8）回退：保留你现有的大矩阵多副本路径
    // -----------------------------
    {
        const int TRI_SIZE = (RowsColsA * RowsColsA - RowsColsA) / 2;
        const int R_REP    = P_PAR * UF;

        static LOUT_T L_rep[R_REP][TRI_SIZE];
#pragma HLS BIND_STORAGE   variable=L_rep type=ram_t2p impl=bram
#pragma HLS ARRAY_PARTITION variable=L_rep dim=1 complete
#pragma HLS RESOURCE       variable=L_rep core=RAM_T2P_BRAM

    col_loop_big:
        for (int j = 0; j < RowsColsA; ++j) {

        prefetch_anchor_big:
            for (int i = j; i < RowsColsA; ++i) {
#pragma HLS PIPELINE II=1
                anchor[i] = LowerTriangularL ? (ACC_T)A[i][j]
                                             : (ACC_T)hls::x_conj(A[j][i]);
            }

            ACC_T squares = ACC_T();
            if (j > 0) {
                const int j_off = row_off(j);
            sum_j_loop_big:
                for (int k = 0; k < j; ++k) {
#pragma HLS PIPELINE II=1
                    LOUT_T v = L_rep[0][j_off + k];
                    rowj[k]  = v;
                    squares += (ACC_T)(hls::x_conj(v) * v);
                }
            }

            ACC_T aii = (ACC_T)A[j][j];
            ADD_T diff = (ADD_T)(aii - squares);

            auto x_real = hls::x_real((DIAG_T)diff);
            if (x_real <= 0) {
#ifndef __SYNTHESIS__
                printf("ERROR: Trying to find the square root of a negative number\n");
#endif
                return_code = 1;
            }

            RDIAG_T rcp_sqrt;
#pragma HLS PIPELINE II=1
            cholesky_rsqrt(x_real, rcp_sqrt);
            diag_recip[j] = rcp_sqrt;

            DIAG_T Ljj_diag = (DIAG_T)(x_real * rcp_sqrt);
            LOUT_T Ljj_out  = (LOUT_T)Ljj_diag;
            diag_out[j]     = Ljj_out;

            if (LowerTriangularL) {
                L[j][j] = (OutputType)Ljj_out;
            } else {
                L[j][j] = (OutputType)hls::x_conj(Ljj_out);
            }

            if (j < RowsColsA - 1) {
            i_batch_loop_big:
                for (int base = j + 1; base < RowsColsA; base += P_PAR) {
                pe_loop_big:
                    for (int p = 0; p < P_PAR; ++p) {
#pragma HLS UNROLL
                        const int i = base + p;
                        if (i < RowsColsA) {

                            ACC_T acc = anchor[i];
                            const int i_off = row_off(i);

                        t_loop_big:
                            for (int t = 0; t < j; t += UF) {
#pragma HLS PIPELINE II=1
                                ACC_T lanes_sum = ACC_T();
                            u_loop_big:
                                for (int u = 0; u < UF; ++u) {
#pragma HLS UNROLL
                                    const int k = t + u;
                                    const int rep_idx = p * UF + u;
                                    if (k < j) {
                                        LOUT_T li = L_rep[rep_idx][i_off + k];
                                        LOUT_T lj = rowj[k];
                                        PROD_T pr = (PROD_T)(-li * hls::x_conj(lj));
                                        lanes_sum += (ACC_T)pr;
                                    }
                                }
                                acc += lanes_sum;
                            }

                            OFF_T sum_off = (OFF_T)acc;
                            OFF_T lij;
                            cholesky_prod_sum_mult(sum_off, diag_recip[j], lij);

                        rep_write_big:
                            for (int rp = 0; rp < R_REP; ++rp) {
#pragma HLS UNROLL
                                L_rep[rp][i_off + j] = (LOUT_T)lij;
                            }

                            if (LowerTriangularL) {
                                L[i][j] = (OutputType)lij;
                                L[j][i] = (OutputType)0;
                            } else {
                                L[j][i] = (OutputType)hls::x_conj(lij);
                                L[i][j] = (OutputType)0;
                            }
                        }
                    }
                }
            }
        } // end col_loop_big

        return return_code;
    }
}

// ===================================================================================================================
// choleskyAlt2: Further improved latency architecture requiring higher resource
template <bool LowerTriangularL, int RowsColsA, typename CholeskyTraits, class InputType, class OutputType>
int choleskyAlt2(const InputType A[RowsColsA][RowsColsA], OutputType L[RowsColsA][RowsColsA]) {
    int return_code = 0;

    // To avoid array index calculations every iteration this architecture uses a simple 2D array rather than a
    // optimized/packed triangular matrix.
    OutputType L_internal[RowsColsA][RowsColsA];
    OutputType prod_column_top;
    typename CholeskyTraits::ACCUM_T square_sum_array[RowsColsA];
    typename CholeskyTraits::ACCUM_T A_cast_to_sum;
    typename CholeskyTraits::ADD_T A_minus_sum;
    typename CholeskyTraits::DIAG_T A_minus_sum_cast_diag;
    typename CholeskyTraits::DIAG_T new_L_diag;
    typename CholeskyTraits::RECIP_DIAG_T new_L_diag_recip;
    typename CholeskyTraits::PROD_T prod;
    typename CholeskyTraits::ACCUM_T prod_cast_to_sum;
    typename CholeskyTraits::ACCUM_T product_sum;
    typename CholeskyTraits::ACCUM_T product_sum_array[RowsColsA];
    typename CholeskyTraits::OFF_DIAG_T prod_cast_to_off_diag;
    typename CholeskyTraits::OFF_DIAG_T new_L_off_diag;
    typename CholeskyTraits::L_OUTPUT_T new_L;

#pragma HLS ARRAY_PARTITION variable = A cyclic dim = CholeskyTraits::UNROLL_DIM factor = CholeskyTraits::UNROLL_FACTOR
#pragma HLS ARRAY_PARTITION variable = L cyclic dim = CholeskyTraits::UNROLL_DIM factor = CholeskyTraits::UNROLL_FACTOR
#pragma HLS ARRAY_PARTITION variable = L_internal cyclic dim = CholeskyTraits::UNROLL_DIM factor = \
    CholeskyTraits::UNROLL_FACTOR
#pragma HLS ARRAY_PARTITION variable = square_sum_array cyclic dim = 1 factor = CholeskyTraits::UNROLL_FACTOR
#pragma HLS ARRAY_PARTITION variable = product_sum_array cyclic dim = 1 factor = CholeskyTraits::UNROLL_FACTOR

col_loop:
    for (int j = 0; j < RowsColsA; j++) {
        // Diagonal calculation
        A_cast_to_sum = A[j][j];
        if (j == 0) {
            A_minus_sum = A_cast_to_sum;
        } else {
            A_minus_sum = A_cast_to_sum - square_sum_array[j];
        }
        if (cholesky_sqrt_op(A_minus_sum, new_L_diag)) {
#ifndef __SYNTHESIS__
            printf("ERROR: Trying to find the square root of a negative number\n");
#endif
            return_code = 1;
        }
        // Round to target format using method specifed by traits defined types.
        new_L = new_L_diag;
        // Generate the reciprocal of the diagonal for internal use to aviod the latency of a divide in every
        // off-diagonal calculation
        A_minus_sum_cast_diag = A_minus_sum;
        cholesky_rsqrt(hls::x_real(A_minus_sum_cast_diag), new_L_diag_recip);
        // Store diagonal value
        if (LowerTriangularL == true) {
            L[j][j] = new_L;
        } else {
            L[j][j] = hls::x_conj(new_L);
        }

    sum_loop:
        for (int k = 0; k <= j; k++) {
// Define average trip count for reporting, loop reduces in length for every iteration of col_loop
#pragma HLS loop_tripcount max = 1 + RowsColsA / 2
            // Same value used in all calcs
            // o Implement -1* here
            prod_column_top = -hls::x_conj(L_internal[j][k]);

        // NOTE: Using a fixed loop length combined with a "if" to implement reducing loop length
        // o Ensures the inner loop can achieve the maximum II (1)
        // o May introduce a small overhead resolving the "if" statement but HLS struggled to schedule when the variable
        //   loop bound expression was used.
        // o Will report inaccurate trip count as it will reduce by one with the col_loop
        // o Variable loop bound code: row_loop: for(int i = j+1; i < RowsColsA; i++) {
        row_loop:
            for (int i = 0; i < RowsColsA; i++) {
// IMPORTANT: row_loop must not merge with sum_loop as the merged loop becomes variable length and HLS will struggle
// with scheduling
#pragma HLS LOOP_FLATTEN off
#pragma HLS PIPELINE II = CholeskyTraits::INNER_II
#pragma HLS UNROLL FACTOR = CholeskyTraits::UNROLL_FACTOR

                if (i > j) {
                    prod = L_internal[i][k] * prod_column_top;
                    prod_cast_to_sum = prod;

                    if (k == 0) {
                        // Prime first sum
                        if (LowerTriangularL == true) {
                            A_cast_to_sum = A[i][j];
                        } else {
                            A_cast_to_sum = hls::x_conj(A[j][i]);
                        }
                        product_sum = A_cast_to_sum;
                    } else {
                        product_sum = product_sum_array[i];
                    }

                    if (k < j) {
                        // Accumulate row sum of columns
                        product_sum_array[i] = product_sum + prod_cast_to_sum;
                    } else {
                        // Final calculation for off diagonal value
                        prod_cast_to_off_diag = product_sum;
                        // Diagonal is stored in its reciprocal form so only need to multiply the product sum
                        cholesky_prod_sum_mult(prod_cast_to_off_diag, new_L_diag_recip, new_L_off_diag);
                        // Round to target format using method specifed by traits defined types.
                        new_L = new_L_off_diag;
                        // Build sum for use in diagonal calculation for this row.
                        if (k == 0) {
                            square_sum_array[j] = hls::x_conj(new_L) * new_L;
                        } else {
                            square_sum_array[j] = hls::x_conj(new_L) * new_L;
                        }
                        // Store result
                        L_internal[i][j] = new_L;
                        // NOTE: Use the upper/lower triangle zeroing in the subsequent loop so the double memory access
                        // does not
                        // become a bottleneck
                        // o Results in a further increase of DSP resources due to the higher II of this loop.
                        // o Retaining the zeroing operation here can give this a loop a max II of 2 and HLS will
                        // resource share.
                        if (LowerTriangularL == true) {
                            L[i][j] = new_L;                                   // Store in lower triangle
                            if (!CholeskyTraits::ARCH2_ZERO_LOOP) L[j][i] = 0; // Zero upper
                        } else {
                            L[j][i] = hls::x_conj(new_L);                      // Store in upper triangle
                            if (!CholeskyTraits::ARCH2_ZERO_LOOP) L[i][j] = 0; // Zero lower
                        }
                    }
                }
            }
        }
    }
    // Zero upper/lower triangle
    // o Use separate loop to ensure main calcuation can achieve an II of 1
    // o As noted above this may increase the DSP resources.
    // o Required when unrolling the inner loop due to array dimension access
    if (CholeskyTraits::ARCH2_ZERO_LOOP) {
    zero_rows_loop:
        for (int i = 0; i < RowsColsA - 1; i++) {
        zero_cols_loop:
            for (int j = i + 1; j < RowsColsA; j++) {
// Define average trip count for reporting, loop reduces in length for every iteration of zero_rows_loop
#pragma HLS loop_tripcount max = 1 + RowsColsA / 2
#pragma HLS PIPELINE
                if (LowerTriangularL == true) {
                    L[i][j] = 0; // Zero upper
                } else {
                    L[j][i] = 0; // Zero lower
                }
            }
        }
    }
    return (return_code);
}

// ===================================================================================================================
// choleskyTop: Top level function that selects implementation architecture and internal types based on the
// traits class provided via the CholeskyTraits template parameter.
// o Call this function directly if you wish to override the default architecture choice or internal types
template <bool LowerTriangularL, int RowsColsA, typename CholeskyTraits, class InputType, class OutputType>
int choleskyTop(const InputType A[RowsColsA][RowsColsA], OutputType L[RowsColsA][RowsColsA]) {
    switch (CholeskyTraits::ARCH) {
        case 0:
            return choleskyBasic<LowerTriangularL, RowsColsA, CholeskyTraits, InputType, OutputType>(A, L);
        case 1:
            return choleskyAlt<LowerTriangularL, RowsColsA, CholeskyTraits, InputType, OutputType>(A, L);
        case 2:
            return choleskyAlt2<LowerTriangularL, RowsColsA, CholeskyTraits, InputType, OutputType>(A, L);
        default:
            return choleskyBasic<LowerTriangularL, RowsColsA, CholeskyTraits, InputType, OutputType>(A, L);
    }
}

/**
* @brief cholesky
*
* @tparam LowerTriangularL   When false generates the result in the upper triangle
* @tparam RowsColsA          Defines the matrix dimensions
* @tparam InputType          Input data type
* @tparam OutputType         Output data type
* @tparam TRAITS             choleskyTraits class
*
* @param matrixAStrm         Stream of Hermitian/symmetric positive definite input matrix
* @param matrixLStrm         Stream of Lower or upper triangular output matrix
*
* @return                    An integer type. 0=Success. 1=Failure. The function attempted to find the square root of
* a negative number i.e. the input matrix A was not Hermitian/symmetric positive definite.
*/
template <bool LowerTriangularL,
          int RowsColsA,
          class InputType,
          class OutputType,
          typename TRAITS = choleskyTraits<LowerTriangularL, RowsColsA, InputType, OutputType> >
int cholesky(hls::stream<InputType>& matrixAStrm, hls::stream<OutputType>& matrixLStrm) {
    InputType A[RowsColsA][RowsColsA];
    OutputType L[RowsColsA][RowsColsA];

    for (int r = 0; r < RowsColsA; r++) {
#pragma HLS PIPELINE
        for (int c = 0; c < RowsColsA; c++) {
            matrixAStrm.read(A[r][c]);
        }
    }

    int ret = 0;
    ret = choleskyTop<LowerTriangularL, RowsColsA, TRAITS, InputType, OutputType>(A, L);

    for (int r = 0; r < RowsColsA; r++) {
#pragma HLS PIPELINE
        for (int c = 0; c < RowsColsA; c++) {
            matrixLStrm.write(L[r][c]);
        }
    }
    return ret;
}

} // end namespace solver
} // end namespace xf
#endif
