# setup environ

export PATH="/home/itemqq/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/:$PATH"

# Erase all data on the chip
# STM32_Programmer_CLI -c port=SWD -e all
STM32_Programmer_CLI -c port=SWD mode=UR -e all

# Download SBSFU with default UserApp
STM32_Programmer_CLI -c port=SWD -d "/home/itemqq/STM32CubeIDE/STM32CubeExpansion_SBSFU_V2.6.2/Projects/STM32F413H-Discovery/Applications/2_Images/2_Images_UserApp/Binary/SBSFU_UserApp.bin" 0x08000000  -v

# STM32_Programmer_CLI -c port=SWD -rst
