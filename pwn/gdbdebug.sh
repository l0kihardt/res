#!/bin/bash
name=$1
a=$(ps -aux | grep "\./$name" | awk '{print $2}' | head -n 1)
echo $a
sudo gdb attach $a
