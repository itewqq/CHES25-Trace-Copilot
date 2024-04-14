#~/bin/bash

set -ex

# /opt/ghidra/support/analyzeHeadless . test_project -deleteProject -import ../binaries/nrf52840_xxaa.bin -postScript cortex-m_headless.py -processor "ARM:LE:32:Cortex" -loader BinaryLoader -loader-baseAddr 0

/opt/ghidra/support/analyzeHeadless . test_project -deleteProject -import ../binaries/nrf52840_xxaa_4algo_O3.bin -postScript cortex-m_headless.py -processor "ARM:LE:32:Cortex" -loader BinaryLoader -loader-baseAddr 0