#!/bin/sh

set -ex


objcopy --input-target=ihex --output-target=binary $1 $2