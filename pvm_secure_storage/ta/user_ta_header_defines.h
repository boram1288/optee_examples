/* SPDX-License-Identifier: MIT */
#include <storage_ta.h>
#define TA_UUID STORAGE_UUID
#define TA_FLAGS (TA_FLAG_EXEC_DDR | TA_FLAG_SINGLE_INSTANCE)
#define TA_STACK_SIZE (16 * 1024)
#define TA_DATA_SIZE (768 * 1024)
#define TA_VERSION "0.1"
#define TA_DESCRIPTION "Protected VM authenticated block storage PoC"
