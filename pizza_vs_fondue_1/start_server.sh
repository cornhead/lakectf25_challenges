#!/bin/bash

mkfifo hcom_fifo
python3 main.py < hcom_fifo | nc -l -p 8000 > hcom_fifo
rm hcom_fifo
