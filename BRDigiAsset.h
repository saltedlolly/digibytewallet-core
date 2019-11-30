//
//  BRDigiAsset.h
//  DigiByte
//
//  Created by Yoshi Jaeger on 05.10.19.
//  Copyright © 2019 DigiByte Foundation NZ Limited. All rights reserved.
//

#ifndef BRDigiAsset_h
#define BRDigiAsset_h

#include "BRAssetData.h"
#include "BRWallet.h"
#include "BRTransaction.h"
#include "BRInt.h"
#include "BRSet.h"
#include <stdint.h>

/*
              DIGI-
      _                _
     /_\  ___ ___  ___| |_ ___
    //_\\/ __/ __|/ _ \ __/ __|
   /  _  \__ \__ \  __/ |_\__ \
   \_/ \_/___/___/\___|\__|___/
 */

//#define EARLIEST_DIGIASSET_TIMESTAMP 1550129416
//#define EARLIEST_ASSET_BLOCKHASH (uint256("3bfffccc01033ad651572cfed8c69f74948c368ddd5669808831f2030fb648c0")) // 8200000
#define EARLIEST_DIGIASSET_TIMESTAMP 1562072262
#define EARLIEST_ASSET_BLOCKHASH (uint256("200275e36faa125a4300f53ff9f66c30fcae8d49ec41eed67854e20af6622b94")) // 9000000

// First word must be zero, second must not be zero
//#define DA_IS_ISSUANCE(byte) ((~(byte) & 0xF0) && ((byte) & 0x0F))
#define DA_IS_ISSUANCE(byte) ((byte) >= 0x01 && (byte) <= 0x06)
// First word must be 1
#define DA_IS_TRANSFER(byte) ((byte) & 0x10)
// First word must be 2
#define DA_IS_BURN(byte)     ((byte) & 0x20)

#define DA_TYPE_SHA1_META_SHA256      0x01
#define DA_TYPE_SHA1_MS12_SHA256      0x02
#define DA_TYPE_SHA1_MS13_SHA256      0x03
#define DA_TYPE_SHA1_META             0x04
#define DA_TYPE_SHA1_NO_META_LOCKED   0x05
#define DA_TYPE_SHA1_NO_META_UNLOCKED 0x06

#define DA_ASSET_DUST_AMOUNT 700

uint8_t BRTXContainsAsset(BRTransaction *tx);

uint8_t BRContainsAsset(const BRTxOutput *outputs, size_t outCount);

uint8_t BROutpointIsAsset(const BRTxOutput* output);

uint8_t BRDecodeAsset(const BRTxOutput* output, BRAssetData* data);

uint8_t BRDecodeAssets(const BRTransaction* tx);

uint8_t BROutpointIsAsset(const BRTxOutput* output);

int BRAssetGetInputTxIds(const BRWallet* wallet, const BRTransaction* tx, BRSet* txIdsOut);

#endif /* BRDigiAsset_h */
