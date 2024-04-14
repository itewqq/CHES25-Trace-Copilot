#!/bin/bash

openocd -f ./interface/jlink.cfg -c "init reset run" -f ./target/nrf52.cfg