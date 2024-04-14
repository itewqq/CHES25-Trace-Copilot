import os
import logging
import math
import os
import serial
import sys
import time

from pwn import *

from ymodem.Protocol import ProtocolType
from ymodem.Socket import ModemSocket

# io = serialtube(SP, baudrate=115200)
# io.recvuntil(b"Selection :")

class TaskProgressBar:
    def __init__(self):
        self.bar_width = 50
        self.last_task_name = ""
        self.current_task_start_time = -1

    def show(self, task_index, task_name, total, success):
        if task_name != self.last_task_name:
            self.current_task_start_time = time.perf_counter()
            if self.last_task_name != "":
                print('\n', end="")
            self.last_task_name = task_name

        success_width = math.ceil(success * self.bar_width / total)

        a = "#" * success_width
        b = "." * (self.bar_width - success_width)
        progress = (success_width / self.bar_width) * 100
        cost = time.perf_counter() - self.current_task_start_time

        print(f"\r{task_index} - {task_name} {progress:.2f}% [{a}->{b}]{cost:.2f}s", end="")

def send_file(sp, filepath):
    logging.basicConfig(level=logging.INFO, format='%(message)s')

    serial_io = serial.Serial()
    serial_io.port = sp
    serial_io.baudrate = "115200"
    serial_io.parity = "N"
    serial_io.bytesize = 8
    serial_io.stopbits = 1
    serial_io.timeout = 2

    try:
        serial_io.open()
    except Exception as e:
        raise Exception("Failed to open serial port!")
    
    def read(size, timeout = 3):
        serial_io.timeout = timeout
        return serial_io.read(size)

    def write(data, timeout = 3):
        serial_io.write_timeout = timeout
        serial_io.write(data)
        serial_io.flush()
        return

    sender = ModemSocket(read, write, ProtocolType.YMODEM)
    
    progress_bar = TaskProgressBar()
    sender.send([filepath], progress_bar.show)

    serial_io.close()
    print("Success!")
    return 

def reset_target():
    cmd = '/home/itemqq/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI -c port=SWD -hardRst'
    output_bytes = subprocess.check_output(cmd, shell=True)
    print(output_bytes.decode('utf-8'))

if __name__ == '__main__':
    sp = "/dev/ttyACM0"
    user_app = "/home/itemqq/STM32CubeIDE/STM32CubeExpansion_SBSFU_V2.6.2/Projects/STM32F413H-Discovery/Applications/2_Images/2_Images_UserApp/Binary/UserApp.sfb"

    # context.log_level = "DEBUG"
    # context.log_file = './log.log'

    # reset target
    reset_target()
    time.sleep(1)
    # select option
    io = serialtube(sp, baudrate=115200)
    io.recvuntil(b"Selection :\r\n\n")
    io.sendline(b"1")
    io.recvuntil(b"YMODEM> Send")
    io.close()
    start_time = time.time()
    send_file(sp, user_app)
    # check result
    io = serialtube(sp, baudrate=115200)
    while True:
        data = io.recvline()
        print(data)
        if b"Selection :" in data:
            break
    end_time = time.time()
    print("Update firmware using :", end_time - start_time, "seconds")
    # io.interactive()
    