#!/bin/bash
set -x

BIN_PATH=$1

openocd -f  interface/stlink.cfg -f target/stm32f4x.cfg -c "program $BIN_PATH  exit 0x8000000"