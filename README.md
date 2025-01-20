# TraceCopilot: A framwork for integrating binary firmware and side-channel information of embedded cryptographic device

## Requirements

- Install Ghidra headless analyzer to `/opt/ghidra/support/analyzeHeadless`.
- Create a ghidra project and hard-link the `src/*.py` files to the source folder of the project.
- In a standalone python env (not Ghidra's):
  - Install required packages: `pwntools`, `capstone`, `keystone`.

## Usage

- In the standalone python env (not Ghidra's):
  - Install required packages: `pwntools`, `capstone`, `keystone`.
  - Run exp_\*_hook_trigger.py with (target binary firmware path, firmware image base address) to make **firmware \#1**.
  - Run exp_\*_hook_hwb_logger.py with (target binary firmware path, firmware image base address) to make **firmware \#2**.
- Execute the **firmware \#1** to get the target side-channel traces and segmentation signals.
- Execute the **firmware \#2** and un-comment the `source ../src/get_pc_trace.py` line in `script/.gdbinit`, using the a ARM debugger to connect the profiling device with the Host PC and get the target addresses sequence.
- Co-Analyse the side-channel trace and the address sequence in `pico/src/pico_trace_process.ipynb`. See the code and comments for details.

>**Update for the revision**: we uploaded the original scripts of firmware handling and trace processing in the ECDSA and random-delayed AES experiments according to the manuscript revision. Please refer to `src/` and `pico/` for the details.
>To reproduce the results, you can download the collected trace files [here](https://drive.google.com/file/d/1Fp6cgyVPmdNk7brx-tQYgUrEvC862Z0r/view?usp=sharing). (We register an *anonymous* Google account to publish this link).
>The binaries could be downloaded from [here](https://1drv.ms/u/c/a7c5ff15f8f8c857/EeQA-3w-ShZBh1HFQ43_qk0BNeOS7QtqNiupiGZF8BmiDg?e=9ZCxK6).
