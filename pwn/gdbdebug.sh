#!/bin/bash
name=$1
a=$(pgrep "$name" | head -n 1)
echo $a
sudo gdb attach $a
