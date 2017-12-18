#!/bin/sh

findcpu()
{ grep 'model name' /proc/cpuinfo | uniq | awk -F':' '{ print $2 }' }

totalmem()
{ grep 'MemTotal' /proc/meminfo | awk -F':' '{ print $2 }' }

echo "CPU Type : $(findcpu)"
echo "Total memory : $(totalmem)"
