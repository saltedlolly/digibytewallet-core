//
//  BRDigiAsset.c
//  DigiByte
//
//  Created by Julian Jäger on 05.10.19.
//  Copyright © 2019 DigiByte Foundation NZ Limited. All rights reserved.
//

#include "BRDigiAsset.h"
#include "BRAssetData.h"
#include "BRWallet.h"
#include "BRTransaction.h"
#include "BRArray.h"
#include <math.h>

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


typedef struct {
    uint8_t exponent;
    uint8_t byteSize;
    uint8_t mantis;
    uint8_t skipBits;
} sffcEntry;

const sffcEntry sffcTable[] = {
    { 0, 1, 5, 3 },
    { 4, 2, 9, 3 },
    { 4, 3, 17, 3 },
    { 4, 4, 25, 3 },
    { 3, 5, 34, 3 },
    { 3, 6, 42, 3 },
    { 0, 7, 54, 2 },
};

/*
 * Returns 1 if asset was decoded correctly, otherwise zero.
 */
uint8_t BRDecodeAsset(const BRTxOutput* output, BRAssetData* data) {
    uint8_t* ptr;
    uint8_t length;
    uint8_t type;

    if (output == NULL || data == NULL) return 0;
    if (!(length = BROutpointIsAsset(output))) return 0;
    ptr = output->script + 4; /* OP_RETURN + LEN + TAG(2) */
    
    memset(data, 0, sizeof(BRAssetData));
    BRAssetInstruction instructions[MAX_INSTRUCTIONS_PER_OP_RETURN];
    size_t instructionCount = 0;
    
    data->version = *ptr;
    ptr++;
    
    type = *ptr;
    
    if (DA_IS_ISSUANCE(type)) {
        data->type = DA_ISSUANCE;
        
        if (type & DA_TYPE_SHA1_META_SHA256) {
            // SHA1 Torrent info_hash + SHA256 of metadata in 80 bytes OP_RETURN
            assert(length == 2 + 1 + 20 + 32 && "Invalid length");
            memcpy(&data->info_hash[0], ptr, 20);
            memcpy(&data->metadata[0], ptr, 32);
            data->has_infohash = 1;
            data->has_metadata = 1;
            
        } else if (type & DA_TYPE_SHA1_MS12_SHA256) {
            // SHA1 torrent info_hash in OP_RETURN
            // SHA256 of metadata in 1(2) multisig
            data->has_infohash = 1;
            data->has_metadata = 2;
            
        } else if (type & DA_TYPE_SHA1_MS13_SHA256) {
            // SHA1 Torrent info_hash
            // and SHA256 of metadata in 1(3) multisig
            data->has_infohash = 3;
            data->has_metadata = 3;
            
        } else if (type & DA_TYPE_SHA1_META) {
            // SHA1 Torrent Hash in OP_RETURN
            // No SHA256 of metadata
            assert(length == 2 + 1 + 20 && "Invalid length");
            memcpy(&data->info_hash[0], ptr, 20);
            data->has_infohash = 1;
            data->has_metadata = 0;
            
        } else if (type & DA_TYPE_SHA1_NO_META_LOCKED) {
            // No Metadata, cannot add rules
            data->has_infohash = 0;
            data->has_metadata = 0;
            data->locked = 1;
            
        } else if (type & DA_TYPE_SHA1_NO_META_UNLOCKED) {
            // No Metadata, can add rules
            data->has_infohash = 0;
            data->has_metadata = 0;
            data->locked = 0;
            
        } else {
            return 0;
        }
        
    } else if (DA_IS_TRANSFER(type)) {
        data->type = DA_TRANSFER;
        uint16_t outputIdx;
        uint8_t inputIdx = 0;
        uint8_t skip = 0, range = 0, percent = 0;
        uint64_t amount = 0;
        
        ++ptr;
        while (ptr - output->script < output->scriptLen - 1) {
            uint8_t flags = *ptr++;
            
            skip = !!(flags & (1 << 7));
            range = !!(flags & (1 << 6));
            percent = !!(flags & (1 << 5));
            outputIdx = flags & (~0xE0);
            if (range) {
                uint8_t outputIdx2 = *ptr++;
                // output size = 13 bits
                outputIdx = outputIdx | (outputIdx2 << 8);
            }
            
            if (percent) {
                amount = *ptr++;
            } else {
                uint8_t flagsLen = (*ptr & 0xe0) >> 5;
                if (flagsLen & 0x0F == 0x07) flagsLen = 6;
                
                assert(flagsLen <= 6 && "sffc out of range");
                sffcEntry* data = &sffcTable[flagsLen];
                amount = UInt64GetBE(ptr); // safe because scriptLen (64) is after script
                ptr += data->byteSize;
                
                // mask flag bits
                for (uint8_t mask0 = 0; mask0 < data->skipBits; ++mask0) {
                    uint64_t mask = (1UL << (63 - mask0));
                    amount &= ~mask;
                }
                
                // shift bits to the LSB
                amount >>= (64 - data->byteSize * 8);
                
                uint64_t expShift = pow(2, data->exponent);
                uint64_t exp = amount % expShift;
                uint64_t mantis = amount / expShift;
                amount = mantis * pow(10, exp);
            }
            
            BRAssetInstruction instruction = { amount, inputIdx, outputIdx };
            instructions[instructionCount++] = instruction;
            
            printf("skip=%d, range=%d, percent=%d, inputIdx=%d, outputIdx=%d, amount=%ld%s\n", skip, range, percent, inputIdx, outputIdx, amount, percent ? "%" : "");
            if (skip) inputIdx++;
        }
        
    } else if (DA_IS_BURN(type)) {
        data->type = DA_BURN;
    }
    
    if (instructionCount > 0) {
        data->instructions = calloc(instructionCount, sizeof(BRAssetInstruction));
        data->instructionsLength = instructionCount;
        memcpy(data->instructions, instructions, instructionCount * sizeof(BRAssetInstruction));
    } else {
        data->instructions = NULL;
    }
    
    /*
     * Note that a buffer length check was performed in
     * BROutpointIsAsset.
     */

    return 1;
}

uint8_t BRDecodeAssets(const BRTransaction* tx) {
    size_t assetDataIdx = 0;
    BRAssetData* data;
    
    printf("txhash = %s\n", u256hex(tx->txHash));
    
    data = &tx->digiassets[assetDataIdx];
        
    // Search for OP_RETURN output
    BRTxOutput* output_opr = NULL;
    for (size_t i = 0; i < tx->outCount; ++i) {
        if (BROutpointIsAsset(&tx->outputs[i])) {
            output_opr = &tx->outputs[i];
            break;
        }
    }
    
    if (output_opr == NULL) return 0;
    
    if (!BRDecodeAsset(output_opr, data)) return 0;
    if (data->has_infohash) {
        // search infohash
        printf("infohash is located in %d\n", data->has_infohash);
    }
    if (data->has_metadata) {
        // search metadata sha256 hash
        printf("Metadatahash is located in %d\n", data->has_metadata);
        
        // search 1(2) or 1(3) multisig output
        BRTxOutput* output;
        for (size_t j = 0; j < tx->outCount; ++j) {
            output = &tx->outputs[j];
            
            if (output->script && output->scriptLen >= 33 && output->script[0] == 1) {
                // multisig
                printf("MultiSig found @ idx=%d\n", j);
            } else {
                output = NULL;
            }
        }
        if (!output) {
            printf("MultiSig not found\n");
        }
    }
    
    return 1;
}

int BRAssetGetInputTxIds(const BRWallet* wallet, const BRTransaction* tx, BRSet* txIdsOut)
{
    int rc = 0;
    
    // Search for OP_RETURN output
    BRTxOutput* output_opr = NULL;
    
    for (size_t i = 0; i < tx->outCount; ++i) {
        // Look for output operation asset
        if (BROutpointIsAsset(&tx->outputs[i])) {
            output_opr = &tx->outputs[i];
            break;
        }
    }
    
    if (output_opr == NULL) return rc;
    
    // Decode assets if not already decoded
    if (!tx->digiassets) BRDecodeAssets(tx);
    
    BRAssetData* assetData = &tx->digiassets[0];
    if (assetData->has_infohash) return rc;
    
    for (size_t i = 0; i < assetData->instructionsLength; ++i) {
        BRAssetInstruction* instruction = &assetData->instructions[i];
        if (instruction->outputIdx >= tx->outCount) continue;
        BRTxOutput* output = &tx->outputs[instruction->outputIdx];
        BRTxInput* input = &tx->inputs[instruction->inputIdx];
        BRUTXO* utxo = (BRUTXO*) input;
        
        if (!BRWalletContainsAddress(wallet, output->address))
            continue;
        
        // Remember input (txID + utxo-idx) and assetData* to track down the issuance
        if (!BRSetContains(txIdsOut, utxo))
            BRSetAdd(txIdsOut, utxo);
    }
    
    rc = 1;
    return rc;
}
