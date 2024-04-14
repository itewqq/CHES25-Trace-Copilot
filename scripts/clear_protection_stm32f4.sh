#!/bin/bash

export PATH="/home/itemqq/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/:$PATH"


# remove rdp-1
STM32_Programmer_CLI -c port=SWD mode=UR --readunprotect

# check the option bytes
STM32_Programmer_CLI -c port=SWD mode=UR -ob displ
STM32_Programmer_CLI -c port=SWD mode=UR -ob SPRMOD=0


# Loop through ids 0 to 10
for id in {0..14}; do
    # Run the STM32_Programmer_CLI command with the current id value
    STM32_Programmer_CLI -c port=SWD mode=UR -ob WRP$id=0
done