#!/usr/bin/env python
#
# Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

import traceback, errno, string, re, sys, time, readelf;

def GetLoadSymbolCommand(EnclaveFile, Base):
    text = readelf.ReadElf(EnclaveFile)
    if text == None:
        return -1
    SegsFile = StringIO(text)

    try:
        FileList = SegsFile.readlines()
        n=4;
        m=100;
        Out = [[[] for ni in range(n)] for mi in range(m)]
        i=0;
        # Parse the readelf output file to extract the section names and
        # their offsets and add the Proj base address.
        textSectionFound = False;
        for line in FileList:
            list = line.split();
            if(len(list) > 0):
                SegOffset = -1;
                # The readelf will put a space after the open bracket for single
                # digit section numbers.  This causes the line.split to create
                # an extra element in the array for these lines.
                if(re.match('\[\s*[0-9]+\]',list[0])):
                    SegOffset = 0;
                if(re.match('\s*[0-9]+\]',list[1])):
                    SegOffset = 1;

                if(SegOffset != -1):
                    if (list[SegOffset+1][0] == '.'):
                        if(list[SegOffset+1].find(".text") != -1):
                            textSectionFound = True;
                            Out[i][0] = list[SegOffset+1];
                            Out[i][1] = str(int(list[SegOffset+3], 16) + int(Base, 10));
                            i = i+1;
                        elif(list[SegOffset+1] == ".tdata"):
                            continue
                        #print "%#08x" % (int(list[SegOffset+3], 16))
                        elif(int(list[SegOffset+3], 16) != 0):
                            Out[i][0] = list[SegOffset+1];
                            Out[i][1] = str(int(list[SegOffset+3], 16) + int(Base, 10));
                            i = i+1;
        if(textSectionFound == True):
            # Write the LLDB 'target modules add' command with all the arguments to the setup LLDB command file.
            lldbcmd = "target modules add " + EnclaveFile;
            lldbcmd += "\n";
            # Write the LLDB 'target modules load' command with all the arguments to the setup LLDB command file.
            lldbcmd += "target modules load --file " + EnclaveFile;
            for j in range(i):
                lldbcmd += " " + Out[j][0] + " " + '%(Location)#08x' % {'Location' : int(Out[j][1])}
            return lldbcmd
        else:
            return -1
    except:
        print ("Error parsing enclave file.  Check format of file.")
        return -1

def GetTextAddr(EnclaveFile, Base):
    text = readelf.ReadElf(EnclaveFile)
    if text == None:
        return -1
    SegsFile = StringIO(text)

    try:
        FileList = SegsFile.readlines()
        # Parse the readelf output file to extract the section names and
        # their offsets and add the Proj base address.
        for line in FileList:
            list = line.split();
            if(len(list) > 0):
                SegOffset = -1;
                # The readelf will put a space after the open bracket for single
                # digit section numbers.  This causes the line.split to create
                # an extra element in the array for these lines.
                if(re.match('\[\s*[0-9]+\]',list[0])):
                    SegOffset = 0;
                if(re.match('\s*[0-9]+\]',list[1])):
                    SegOffset = 1;

                if(SegOffset != -1):
                    if (list[SegOffset+1][0] == '.'):
                        # If it is the .text section, get the .text start address and plus enclave start address
                        if(list[SegOffset+1].find(".text") != -1):
                            return int(list[SegOffset+3], 16) + int(Base, 10)

    except:
        print ("Error parsing enclave file.  Check format of file.")
        return -1
