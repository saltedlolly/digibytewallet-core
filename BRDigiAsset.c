//
//  BRDigiAsset.c
//  DigiByte
//
//  Created by Julian Jäger on 05.10.19.
//  Copyright © 2019 DigiByte Foundation NZ Limited. All rights reserved.
//

#include "BRDigiAsset.h"
#include "BRWallet.h"
#include "BRTransaction.h"
#include "BRArray.h"

uint8_t BRTXContainsAsset(BRTransaction *tx)
{
    return BRContainsAsset(tx->outputs, tx->outCount);
}

uint8_t BRContainsAsset(const BRTxOutput *outputs, size_t outCount)
{
    for (int p = 0; p < outCount; p++)
        if (BROutpointIsAsset(&outputs[p])) return 1;
    return 0;
}

/* (internal)
 * Tests the protocol tag of an asset.
 * Returns 1 if the test was successful, otherwise it returns zero.
 */
uint8_t BRTestProtocolTag(const uint8_t* ptr, const char* check) {
    if (ptr == NULL || check == NULL) return 0;
    return (*ptr == check[0] && *(ptr + 1) == check[1]);
}

/*
 * Returns zero if an outpoint is no asset, otherwise
 * returns the length of the asset's data
 */
uint8_t BROutpointIsAsset(const BRTxOutput* output)
{
    uint8_t* ptr;
    uint8_t length;

    if (output->scriptLen <= 6 || !output->script) return 0;
    ptr = output->script;

    if (*ptr != OP_RETURN) return 0;
    ++ptr;

    length = *ptr;
    if (length == 0 || length + 2 > output->scriptLen) return 0;
    ++ptr;

    if (!BRTestProtocolTag(ptr, "DA")) return 0;
    ++ptr;

//    if (*ptr == 0x02) return 0;
    return length;
}

/*
 * Returns 1 if asset was decoded correctly, otherwise zero.
 */
uint8_t BRDecodeAsset(const BRTxOutput* output, BRAssetData* data) {
    uint8_t* ptr;
    uint8_t length;
    uint8_t type;

    if (output == NULL || data == NULL) return 0;
    if (!(length = BROutpointIsAsset(output))) return 0;
    ptr = output->script + 4; /* OP_RETURN + LEN + TAG */
    
    memset(data, 0, sizeof(BRAssetData));
    
    data->version = *ptr;
    ptr++;
    
    type = *ptr;
    
    if (DA_IS_ISSUANCE(type)) {
        data->type = DA_ISSUANCE;
    } else if (DA_IS_TRANSFER(type)) {
        data->type = DA_TRANSFER;
    } else if (DA_IS_BURN(type)) {
        data->type = DA_BURN;
    }
    
    /*
     * Note that a buffer length check was performed in
     * BROutpointIsAsset.
     */
    if (type & DA_TYPE_SHA1_META_SHA256) {
        assert(length == 2 + 1 + 20 + 32 && "Invalid length");
        memcpy(&data->info_hash[0], ptr, 20);
        memcpy(&data->metadata[0], ptr, 32);
        data->has_infohash = 1;
        data->has_metadata = 1;
        
    } else if (type & DA_TYPE_SHA1_MS12_SHA256) {
        
    } else if (type & DA_TYPE_SHA1_MS13_SHA256) {
        
    } else if (type & DA_TYPE_SHA1_META) {
        assert(length == 2 + 1 + 20 && "Invalid length");
        memcpy(&data->info_hash[0], ptr, 20);
        data->has_infohash = 1;
        
    } else if (type & DA_TYPE_SHA1_NO_META_LOCKED) {
        data->locked = 1;
        
    } else if (type & DA_TYPE_SHA1_NO_META_UNLOCKED) {
        data->locked = 0;
        
    } else {
    }
    
    return 1;
}


