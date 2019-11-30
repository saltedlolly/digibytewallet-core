//
//  BRAssetData.h
//  DigiByte
//
//  Created by Yoshi Jaeger on 05.10.19.
//  Copyright © 2019 DigiByte Foundation NZ Limited. All rights reserved.
//

#include "BRInt.h"

#ifndef BRAssetData_h
#define BRAssetData_h

#include <stdint.h>

#define MAX_INSTRUCTIONS_PER_OP_RETURN 40

typedef enum {
    DA_UNDEFINED,
    DA_ISSUANCE,
    DA_TRANSFER,
    DA_BURN
} BRAssetOperationType;

typedef struct {
    // percent and range are not yet supported in version 0x02
    uint64_t amount;
    unsigned int inputIdx;
    unsigned int outputIdx;
} BRAssetInstruction;

typedef struct {
    uint8_t info_hash[20];
    uint8_t metadata[32];
    
    uint8_t version;
    uint8_t has_metadata;
    uint8_t has_infohash;
    BRAssetOperationType type;
    uint8_t locked;
    
    BRAssetInstruction* instructions;
    size_t instructionsLength;
} BRAssetData;

BRAssetData* BRAssetDataNew(size_t count);
void BRAssetDataFree(BRAssetData* assetData);

#endif /* BRAssetData_h */
