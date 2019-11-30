//
//  BRAssetData.c
//  DigiByte
//
//  Created by Julian Jäger on 05.10.19.
//  Copyright © 2019 DigiByte Foundation NZ Limited. All rights reserved.
//

#include "BRAssetData.h"
#include <stdlib.h>

BRAssetData* BRAssetDataNew(size_t count) {
    BRAssetData* assetData = calloc(count, sizeof(BRAssetData));
    return assetData;
}

void BRAssetDataFree(BRAssetData* assetData) {
    if (assetData != NULL) free(assetData);
}
