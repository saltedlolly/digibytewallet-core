#!/bin/sh

gcc -o /tmp/test -I secp256k1/ *.c crypto/*.c crypto/sha3/*.c && /tmp/test
