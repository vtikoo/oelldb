# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

from __future__ import print_function
import lldb
import struct
import subprocess
import os.path
from ctypes import create_string_buffer
import load_symbol_cmd

POINTER_SIZE = 8

# These constant definitions must align with oe_debug_enclave_t structure defined in debugrt/host.h
class oe_debug_enclave_t:
    OFFSETOF_MAGIC = 0
    SIZEOF_MAGIC = 8
    MAGIC_VALUE = 0xabc540ee14fa48ce

    OFFSETOF_VERSION = 8
    SIZEOF_VERSION = 8

    OFFSETOF_NEXT = 16
    SIZEOF_NEXT = 8

    OFFSETOF_PATH = 24
    SIZEOF_PATH = 8

    OFFSETOF_PATH_LENGTH = 32
    SIZEOF_PATH_LENGTH = 8

    OFFSETOF_BASE_ADDRESS = 40
    SIZEOF_BASE_ADDRESS = 8

    OFFSETOF_SIZE = 48
    SIZEOF_SIZE = 8

    OFFSETOF_TCS_ARRAY = 56
    SIZEOF_TCS_ARRAY = 8

    OFFSETOF_NUM_TCS = 64
    SIZEOF_NUM_TCS = 8

    OFFSETOF_FLAGS = 72
    SIZEOF_FLAGS = 8
    MASK_DEBUG = 0x01
    MASK_SIMULATE = 0x02

    def __init__(self, addr):
        if addr:
            self.magic = read_int_from_memory(addr + self.OFFSETOF_MAGIC, self.SIZEOF_MAGIC)
        if not self.is_valid():
            return

        self.version = read_int_from_memory(addr + self.OFFSETOF_VERSION, self.SIZEOF_VERSION)
        self.next = read_int_from_memory(addr + self.OFFSETOF_NEXT, self.SIZEOF_NEXT)

        path = read_int_from_memory(addr + self.OFFSETOF_PATH, self.SIZEOF_PATH)
        path_length = read_int_from_memory(addr + self.OFFSETOF_PATH_LENGTH, self.SIZEOF_PATH_LENGTH)
        self.path = bytes(read_from_memory(path, path_length)).decode('utf-8')

        self.base_address = read_int_from_memory(addr + self.OFFSETOF_BASE_ADDRESS, self.SIZEOF_BASE_ADDRESS)

        self.tcs = []
        self.num_tcs = read_int_from_memory(addr + self.OFFSETOF_NUM_TCS, self.SIZEOF_NUM_TCS)
        tcs_ptr = read_int_from_memory(addr + self.OFFSETOF_TCS_ARRAY, self.SIZEOF_TCS_ARRAY)
        for i in range(0, self.num_tcs):
            tcs = read_int_from_memory(tcs_ptr, 8) # sizeof pointer is hard-coded to 8
            self.tcs.append(tcs)
            tcs_ptr += 8

        flags = read_int_from_memory(addr + self.OFFSETOF_FLAGS, self.SIZEOF_FLAGS)
        self.debug = bool(flags & self.MASK_DEBUG)
        self.simulate = bool(flags & self.MASK_SIMULATE)


    def is_valid(self):
        return self.magic == self.MAGIC_VALUE

class oe_debug_image_t:
    OFFSETOF_MAGIC = 0
    SIZEOF_MAGIC = 8
    MAGIC_VALUE  = 0xecd538d85d491d0b

    OFFSETOF_VERSION = 8
    SIZEOF_VERSION = 8

    OFFSETOF_PATH = 16
    SIZEOF_PATH = 8

    OFFSETOF_PATH_LENGTH = 24
    SIZEOF_PATH_LENGTH = 8

    OFFSETOF_BASE_ADDRESS = 32
    SIZEOF_BASE_ADDRESS = 8

    OFFSETOF_SIZE = 40
    SIZEOF_SIZE = 8

    def __init__(self, addr):
        if addr:
            self.magic = read_int_from_memory(addr + self.OFFSETOF_MAGIC, self.SIZEOF_MAGIC)
        if not self.is_valid():
            return

        self.version = read_int_from_memory(addr + self.OFFSETOF_VERSION, self.SIZEOF_VERSION)
        path = read_int_from_memory(addr + self.OFFSETOF_PATH, self.SIZEOF_PATH)
        path_length = read_int_from_memory(addr + self.OFFSETOF_PATH_LENGTH, self.SIZEOF_PATH_LENGTH)
        self.path = bytes(read_from_memory(path, path_length)).decode('utf-8')
        self.base_address = read_int_from_memory(addr + self.OFFSETOF_BASE_ADDRESS, self.SIZEOF_BASE_ADDRESS)

    def is_valid(self):
        return self.magic == self.MAGIC_VALUE

# This constant definition must align with sgx_tcs_t
TCS_GSBASE_OFFSET =  56

# The set to store all loaded OE enclave base address.
g_loaded_oe_enclave_addrs = set()

# Global enclave list parsed flag
g_enclave_list_parsed = False

def read_from_memory(addr, size):
    process = lldb.debugger.GetSelectedTarget().GetProcess()
    """Read data with specified size  from the specified memory"""
    # ( check the address is inside the enclave)
    if addr == 0:
        print ("Error happens in read_from_memory: addr = {0:x}".format(int(addr)))
        return None

    # process.ReadMemory() returns "memory read failed for" error while reading tcs_addr at least in lldb-7 and earlier 
    # that's why use system call to read memory
    pid = process.GetProcessID()

    fd = os.open("/proc/" + str(pid) + "/mem", os.O_RDONLY)
    os.lseek(fd, int(addr), 0)
    memory = os.read(fd, size)
    os.close(fd)

    if memory != -1:
        return memory
    else:
        print ("Can't access memory at {0:x}.".format(int(addr)) + "\n" + str(os.error))
        return None

def read_int_from_memory(addr, size):
    mv = read_from_memory(addr, size)
    return int.from_bytes(mv, 'little')

def target_path_to_host_path(target_path):
    so_name = os.path.basename(target_path)
    strpath = gdb.execute("show solib-search-path", False, True)
    path = strpath.split()[-1]
    strlen = len(path)
    if strlen != 1:
        path = path[0:strlen-1]
    host_path = path + "/" + so_name
    return host_path

def load_enclave_symbol(enclave_path, enclave_base_addr):
    """Load enclave symbol file into current debug session"""

    if os.path.exists(enclave_path) == True:
        enclave_path = os.path.abspath(enclave_path)
    else:
        enclave_path = target_path_to_host_path(enclave_path)
    lldb_cmd = load_symbol_cmd.GetLoadSymbolCommand(enclave_path, str(enclave_base_addr))
    if lldb_cmd == -1:
        print ("Can't get symbol loading command.")
        return False
    
    commands = lldb_cmd.split('\n')
    for cmd in commands:
        lldb.debugger.HandleCommand(cmd)
        #print(cmd)

    # Store the oe_enclave address to global set that will be cleanup on exit.
    global g_loaded_oe_enclave_addrs
    arg_list = lldb_cmd.split();
    g_loaded_oe_enclave_addrs.add(int(arg_list[arg_list.index(".text") + 1], 16))
    return True

def unload_enclave_symbol(target, enclave_path, enclave_base_addr):
    if os.path.exists(enclave_path) == True:
        enclave_path = os.path.abspath(enclave_path)
    else:
        enclave_path = target_path_to_host_path(enclave_path)

    thread = frame.GetThread();
    process = thread.GetProcess();
    target = process.GetTarget()
    
    module = target.FindModule(lldb.SBFileSpec(enclave_path.encode('utf-8')))
    target.RemoveModule(module)
    text_addr = load_symbol_cmd.GetTextAddr(enclave_path, str(enclave_base_addr))
    global g_loaded_oe_enclave_addrs
    g_loaded_oe_enclave_addrs.discard(text_addr)

    return True

def set_tcs_debug_flag(tcs_addr):
    string = read_from_memory(tcs_addr + 8, 4)
    if string is None:
        return False
    flag = struct.unpack('I', string)[0]
    flag |= 1

    process = lldb.debugger.GetSelectedTarget().GetProcess()    
    pid = process.GetProcessID();
    fd = os.open("/proc/" + str(pid) + "/mem", os.O_WRONLY)
    os.lseek(fd, int(tcs_addr + 8), 0);
    result = os.write(fd, struct.pack('I', flag));
    os.close(fd)
    if result != -1:
        return True
    else:
        print ("Can't access memory at {0:x}.".format(int(addr)) + "\n" + str(os.error))
        return None
    
def enable_oeenclave_debug(oe_enclave_addr):
    """For a given OE enclave, load its symbol and enable debug flag for all its TCS"""

    enclave = oe_debug_enclave_t(oe_enclave_addr)

    # Check if magic matches
    if not enclave.is_valid():
        return False

    # No version specific checks.
    # The contract will be extended in backwards compatible manner.
    # Debugger may use version to take specific actions in future.

    # Check if debugging is enabled.
    if enclave.debug == 0:
        print ("oegdb: Debugging not enabled for enclave %s" % enclave.path)
        return False

    # Check if the enclave is loaded in simulation mode.
    if enclave.simulate != 0:
        print ("oegdb: Enclave %s loaded in simulation mode" % enclave.path)

    # Load symbols for the enclave
    if load_enclave_symbol(enclave.path, enclave.base_address) != 1:
        return False

    print("oegdb: Symbols loaded for enclave \n")
    for tcs in enclave.tcs:
        set_tcs_debug_flag(tcs)

    print("oegdb: All tcs set to debug for enclave \n")
    return True

def unload_enclave_symbol(enclave_path, enclave_base_addr):
    if os.path.exists(enclave_path) == True:
        enclave_path = os.path.abspath(enclave_path)
    else:
        enclave_path = target_path_to_host_path(enclave_path)

    target = lldb.debugger.GetSelectedTarget()
    module = target.FindModule(lldb.SBFileSpec(enclave_path))
    target.RemoveModule(module)
    
    text_addr = load_symbol_cmd.GetTextAddr(enclave_path, str(enclave_base_addr))
    global g_loaded_oe_enclave_addrs
    g_loaded_oe_enclave_addrs.discard(text_addr)


class EnclaveCreationBreakpoint:
    def __init__(self, target):
        breakpoint  = target.BreakpointCreateByName("oe_notify_debugger_enclave_creation")
        breakpoint.SetScriptCallbackFunction('oelldb.EnclaveCreationBreakpoint.onHit')

    @staticmethod
    def onHit(frame, bp_loc, dict):
        enclave_addr = frame.FindValue("rdi", lldb.eValueTypeRegister ).signed
        enable_oeenclave_debug(enclave_addr)
        return False

class EnclaveTerminationBreakpoint:
    def __init__(self, target):
        breakpoint  = target.BreakpointCreateByName("oe_notify_debugger_enclave_termination")
        breakpoint.SetScriptCallbackFunction('oelldb.EnclaveTerminationBreakpoint.onHit')

    @staticmethod
    def onHit(frame, bp_loc, dict):
        enclave_addr = frame.FindValue("rdi", lldb.eValueTypeRegister ).signed
        enclave = oe_debug_enclave_t(enclave_addr)
        unload_enclave_symbol(enclave.path, enclave.base_address)
        return False

class LibraryLoadBreakpoint:
    def __init__(self, target):
        breakpoint = target.BreakpointCreateByName("oe_notify_debugger_library_load")
        breakpoint.SetScriptCallbackFunction('oelldb.LibraryLoadBreakpoint.onHit')

    @staticmethod
    def onHit(frame, bp_loc, dict):
        library_image_addr = frame.FindValue("rdi", lldb.eValueTypeRegister).signed
        library_image = oe_debug_image_t(library_image_addr)
        load_enclave_symbol(library_image.path, library_image.base_address)
        return False

class LibraryUnloadBreakpoint:
    def __init__(self, target):
        breakpoint = target.BreakpointCreateByName("oe_notify_debugger_library_unload")
        breakpoint.SetScriptCallbackFunction('oelldb.LibraryUnloadBreakpoint.onHit')

    @staticmethod
    def onHit(frame, bp_loc, dict):
        library_image_addr = frame.FindValue("rdi", lldb.eValueTypeRegister).signed
        library_image = oe_debug_image_t(library_image_addr)
        unload_enclave_symbol(library_image.path, library_image.base_address)
        return False

def oe_debugger_init(debugger):
    # TODO: Initialize when there is no target yet
    EnclaveCreationBreakpoint(debugger.GetSelectedTarget())
    EnclaveTerminationBreakpoint(debugger.GetSelectedTarget())
    LibraryLoadBreakpoint(debugger.GetSelectedTarget())
    LibraryUnloadBreakpoint(debugger.GetSelectedTarget())

# Invoked when `command script import oelldb is called.    
def __lldb_init_module(debugger, dict):
    oe_debugger_init(debugger)
