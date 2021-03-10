#!/bin/sh

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
rm liboe_ptrace.so 2>/dev/null
rm -rf build
mkdir build
cd build
cmake ../ptraceLib
make
cp libsgxptrace.so ../liboe_ptrace.so

