/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - vaguely configurable bits
   ----------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>
*/

#ifndef _HAVE_CONFIG_H
#define _HAVE_CONFIG_H

#include "types.h"

/* Version string: */

#define VERSION             "2.56b"

/******************************************************
 *                                                    *
 *  Settings that may be of interest to power users:  *
 *                                                    *
 ******************************************************/

/* 注释掉取消使用终端颜色 */

#define USE_COLOR

/* 注释掉可以使用低配的7位UI */

#define FANCY_BOXES

/* 模糊代码的默认超时（毫秒）。这是上限，也用于检测挂起；实际值是自动缩放的 */

#define EXEC_TIMEOUT        1000

/* 自动缩放时的超时四舍五入因子（毫秒） */

#define EXEC_TM_ROUND       20

/* 64位arch宏 */
#if (defined (__x86_64__) || defined (__arm64__) || defined (__aarch64__))
#define WORD_SIZE_64 1
#endif

/* 子进程的默认内存限制（MB） */

#ifndef WORD_SIZE_64
#  define MEM_LIMIT         25
#else
#  define MEM_LIMIT         50
#endif /* ^!WORD_SIZE_64 */

/* 在QEMU模式下运行时的默认内存限制（MB）： */

#define MEM_LIMIT_QEMU      200

/* 每个新测试用例（以及显示出可变行为的测试用例）的校准周期数： */

#define CAL_CYCLES          8
#define CAL_CYCLES_LONG     40

/* 放弃输入文件后的后续超时次数： */

#define TMOUT_LIMIT         250

/* 记录的unique hangs或crashes 的最大次数： */

#define KEEP_UNIQUE_HANG    500
#define KEEP_UNIQUE_CRASH   5000

/* 单个“havoc”阶段的随机调整的基准数量 */

#define HAVOC_CYCLES        256
#define HAVOC_CYCLES_INIT   1024

/* 上面的最大乘数（应为2的幂，请注意32位int溢出）: */

#define HAVOC_MAX_MULT      16

/* havoc周期的绝对最小数目（所有调整之后）： */

#define HAVOC_MIN           16

/* havoc-stage调整的最大堆叠量。 实际值是这样计算的: 

   n = random between 1 and HAVOC_STACK_POW2
   stacking = 2^n

   换句话说，默认值（n = 7）产生2、4、8、16、32、64或128个堆叠的调整: */

#define HAVOC_STACK_POW2    7

/* 限制块大小以进行克隆和删除操作。 这些范围中的每一个都有33％的概率被选中，除了前两个周期更喜欢较小的块: */

#define HAVOC_BLK_SMALL     32
#define HAVOC_BLK_MEDIUM    128
#define HAVOC_BLK_LARGE     1500

/* 特大块，很少选择（<5％的时间）: */

#define HAVOC_BLK_XL        32768

/* 跳过队列中不受欢迎的条目的概率，以百分比表示: */

#define SKIP_TO_NEW_PROB    99 /* 新的, 待定收藏夹 */
#define SKIP_NFAV_OLD_PROB  95 /* 旧的,cur入口已经fuzz */
#define SKIP_NFAV_NEW_PROB  75 /* 旧的, cur入口还没fuzz */

/* splice周期数：*/

#define SPLICE_CYCLES       15

/* 标准的每个splice的havoc周期长度： */

#define SPLICE_HAVOC        32

/* 整数加减法的最大偏移量 */

#define ARITH_MAX           35

/* 测试用例微调器的限制。 绝对最小块大小；以及切入输入文件的开始和结束除数：*/

#define TRIM_MIN_BYTES      4
#define TRIM_START_STEPS    16
#define TRIM_END_STEPS      1024

/* 输入文件的最大大小，以字节为单位（保持在100MB以下）: */

#define MAX_FILE            (1 * 1024 * 1024)

/* 同样，对于测试用例最小化器: */

#define TMIN_MAX_FILE       (10 * 1024 * 1024)

/* afl-tmin的块标准化步骤: */

#define TMIN_SET_MIN_SIZE   4
#define TMIN_SET_STEPS      128

/* 最大dictionary tokens大小（-x），以字节为单位: */

#define MAX_DICT_FILE       128

/* 自动检测的dictionary tokens的长度限制: */

#define MIN_AUTO_EXTRA      3
#define MAX_AUTO_EXTRA      32

/* 确定性步骤中要使用的用户指定的dictionary tokens的最大数量； 
超过这一点，仍然会执行“extras/user”步骤，但是几率会降低: */

#define MAX_DET_EXTRAS      200

/* 实际在模糊测试中使用的最大数量的自动提取的dictionary tokens（第一个值），
并作为候选保留在内存中。 后者应该比前者高得多. */

#define USE_AUTO_EXTRAS     50
#define MAX_AUTO_EXTRAS     (USE_AUTO_EXTRAS * 10)

/* effector map的比例因子用于跳过一些更昂贵的确定性步骤。
 实际除数设置为2 ^ EFF_MAP_SCALE2个字节: */

#define EFF_MAP_SCALE2      3

/* effector logic插入的最小输入文件长度 */

#define EFF_MIN_LEN         128

/* effector density最大值,超过该密度后，所有事物都会无条件fuzz（％）: */

#define EFF_MAX_PERC        90

/* UI 刷新频率 (Hz): */

#define UI_TARGET_HZ        5

/* Fuzzer统计信息文件和绘图更新间隔（秒）: */

#define STATS_UPDATE_SEC    60
#define PLOT_UPDATE_SEC     5

/* 用于CPU负载和执行速度统计信息的平滑除数（1到不进行平滑）. */

#define AVG_SMOOTHING       16

/* 同步间隔 (每n个havoc cycles): */

#define SYNC_INTERVAL       5

/* 输出目录重用宽限期 (minutes): */

#define OUTPUT_GRACE        25

/* 取消使用简单文件名的注释 (id_NNNNNN): */

// #define SIMPLE_FILES

/* 用于fuzzing的interesting values */

#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */

/***********************************************************
 *                                                         *
 *  您可能不想接触的真正奇特的东西:                          *
 *                                                         *
 ***********************************************************/

/* 从/dev/urandom重新播种libc PRNG之间的调用计数间隔: */

#define RESEED_RNG          10000

/* 从GCC传递到“ as”并用于解析配置文件的最大行长: */

#define MAX_LINE            8192

/* 用于将SHM ID传递给被调用程序的环境变量. */

#define SHM_ENV_VAR         "__AFL_SHM_ID"

/* 其他不太有趣的仅供内部使用的变量. */

#define CLANG_ENV_VAR       "__AFL_CLANG_MODE"
#define AS_LOOP_ENV_VAR     "__AFL_AS_LOOPCHECK"
#define PERSIST_ENV_VAR     "__AFL_PERSISTENT"
#define DEFER_ENV_VAR       "__AFL_DEFER_FORKSRV"

/* 延迟和持久模式的代码内签名. */

#define PERSIST_SIG         "##SIG_AFL_PERSISTENT##"
#define DEFER_SIG           "##SIG_AFL_DEFER_FORKSRV##"

/* 独特的位图签名用于指示执行失败: */

#define EXEC_FAIL_SIG       0xfee1dead

/* 独特的退出代码，用于指示MSAN跳闸情况: */

#define MSAN_ERROR          86

/* forkserver命令的指定文件描述符(应用程序将使用FORKSRV_FD和FORKSRV_FD + 1): */

#define FORKSRV_FD          198

/* Fork服务器初始化超时倍增器：
我们将等待用户选择的超时时间加上这一时间，以便Fork服务器启动. */

#define FORK_WAIT_MULT      10

/* 校准超时调整，
在恢复模糊测试会话或尝试校准已经添加的内部发现时要更加慷慨。 
第一个值是百分比，其他值以毫秒为单位: */

#define CAL_TMOUT_PERC      125
#define CAL_TMOUT_ADD       50

/* 放弃之前校准案例的机会数量: */

#define CAL_CHANCES         3

/* 跟踪的二进制文件的映射大小（2 ^ MAP_SIZE_POW2）。必须大于2；
 您可能出于性能原因而希望将其保持在18以下
 （在编译时调整AFL_INST_RATIO可能是解决复杂程序问题的更好方法）。
  更改此选项后，您需要重新编译目标二进制文件-否则，可能会发生SEGV. */

#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)

/* 最大分配器请求大小（保持在INT_MAX以下）: */

#define MAX_ALLOC           0x40000000

/* 伪造的哈希种子: */

#define HASH_CONST          0xa5b35705

/* afl-gotcpu用于控制忙循环定时的常量: */

#define  CTEST_TARGET_MS    5000
#define  CTEST_CORE_TRG_MS  1000
#define  CTEST_BUSY_CYCLES  (10 * 1000 * 1000)

/* 取消注释以使用劣质的基于块覆盖的检测。 
请注意，您需要重新编译目标二进制文件才能生效: */

// #define COVERAGE_ONLY

/*取消注释此操作将忽略命中计数，并且每个元组仅输出一位。
  与之前的设置一样，您将需要重新编译目标二进制文件: */

// #define SKIP_COUNTS

/* 取消注释此选项可使用检测数据记录新发现的路径，
但不要将其用作模糊测试的种子。 
这对于方便地测量“哑”模糊算法可以实现的覆盖范围很有用: */

// #define IGNORE_FINDS

#endif /* ! _HAVE_CONFIG_H */
