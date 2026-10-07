/* SPDX-License-Identifier: MIT */
#ifndef STORAGE_TA_H
#define STORAGE_TA_H
#define STORAGE_UUID {0xb720dc9e,0x0e8b,0x44f1,{0x93,0xa4,0x22,0x9b,0x8c,0x81,0xe0,0x37}}
#define STORAGE_GUARD_UUID {0x2fc0af42,0x31e4,0x4ce1,{0x96,0x24,0xe4,0x41,0xb1,0x1c,0x6a,0x93}}
#define SS_INIT 0
#define SS_QUERY 1
#define SS_ENCRYPT 2
#define SS_DECRYPT 3
#define SS_COMMIT 4
#define SS_BLOCK_SIZE 4096U
#define SS_RECORD_SIZE 8192U
#define SS_BLOCKS 2048U
#define SS_VOLUME_ID 0x53535031U
/* INIT value.a: 0=existing only, 1=explicit new provisioning; b=volume ID. */
#endif
