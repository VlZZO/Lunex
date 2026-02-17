import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import re
import shutil
from pathlib import Path
from typing import Dict, List, Any, Tuple
import sys
import traceback
import time
import ctypes
import struct
import threading
from dataclasses import dataclass
from ctypes import wintypes

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("AVISO: psutil não instalado. O hot-reload não funcionará. Instale com: pip install psutil")

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_RELEASE = 0x00008000

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008

PAGE_EXECUTE_ANY = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD
]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

kernel32.VirtualFreeEx.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD
]
kernel32.VirtualFreeEx.restype = wintypes.BOOL

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE, wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
    wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

class MemoryOperations:
    @staticmethod
    def read_bytes(handle: int, address: int, length: int) -> bytes:
        buffer = ctypes.create_string_buffer(length)
        bytes_read = ctypes.c_size_t()
        success = kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(address), buffer, length, ctypes.byref(bytes_read)
        )
        return buffer.raw[: bytes_read.value] if success else b""
    
    @staticmethod
    def write_bytes(handle: int, address: int, data: bytes) -> bool:
        bytes_written = ctypes.c_size_t()
        return bool(kernel32.WriteProcessMemory(
            handle, ctypes.c_void_p(address), data, len(data), ctypes.byref(bytes_written)
        ))
    
    @staticmethod
    def read_uint32(handle: int, address: int) -> int:
        data = MemoryOperations.read_bytes(handle, address, 4)
        return struct.unpack("<I", data)[0] if len(data) == 4 else 0
    
    @staticmethod
    def read_int64(handle: int, address: int) -> int:
        data = MemoryOperations.read_bytes(handle, address, 8)
        return struct.unpack("<Q", data)[0] if len(data) == 8 else 0
    
    @staticmethod
    def write_int64(handle: int, address: int, value: int) -> bool:
        data = struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
        return MemoryOperations.write_bytes(handle, address, data)
    
    @staticmethod
    def write_int8(handle: int, address: int, value: int) -> bool:
        data = struct.pack("<B", value & 0xFF)
        return MemoryOperations.write_bytes(handle, address, data)
    
    @staticmethod
    def allocate_memory(handle: int, size: int, protect: int) -> int:
        return kernel32.VirtualAllocEx(handle, None, size, MEM_COMMIT | MEM_RESERVE, protect)
    
    @staticmethod
    def free_memory(handle: int, address: int, size: int) -> bool:
        return bool(kernel32.VirtualFreeEx(handle, address, size, MEM_RELEASE))
    
    @staticmethod
    def create_remote_thread(handle: int, start_address: int) -> int:
        thread_id = wintypes.DWORD()
        return kernel32.CreateRemoteThread(
            handle, None, 0, start_address, None, 0, ctypes.byref(thread_id)
        )
    
    @staticmethod
    def wait_for_thread(handle: int, timeout: int = 30000) -> int:
        return kernel32.WaitForSingleObject(handle, timeout)
    
    @staticmethod
    def close_handle(handle: int) -> bool:
        return bool(kernel32.CloseHandle(handle))

class AOBScanner:
    def __init__(self, process_handle: int, base_address: int, module_size: int):
        self.read_memory = {}
        mem_region_addr = base_address
        main_module_end = base_address + module_size
        
        while mem_region_addr < main_module_end:
            mem_info = MEMORY_BASIC_INFORMATION()
            query_result = kernel32.VirtualQueryEx(
                process_handle, ctypes.c_void_p(mem_region_addr),
                ctypes.byref(mem_info), ctypes.sizeof(mem_info)
            )
            if query_result == 0:
                break
            
            if (mem_info.State & MEM_COMMIT) and (mem_info.Protect & PAGE_GUARD) == 0 and (mem_info.Protect & PAGE_EXECUTE_ANY):
                region_data = MemoryOperations.read_bytes(
                    process_handle, mem_info.BaseAddress, mem_info.RegionSize
                )
                if region_data:
                    self.read_memory[mem_info.BaseAddress] = region_data
            
            mem_region_addr = mem_info.BaseAddress + mem_info.RegionSize
    
    def scan(self, pattern: list) -> int:
        for base_address, memory_data in self.read_memory.items():
            index = self._search_pattern(memory_data, pattern)
            if index != -1:
                return base_address + index
        return 0
    
    def _search_pattern(self, data: bytes, pattern: list) -> int:
        data_len = len(data)
        pattern_len = len(pattern)
        for i in range(data_len - pattern_len + 1):
            match = True
            for j in range(pattern_len):
                if pattern[j] is not None and pattern[j] != data[i + j]:
                    match = False
                    break
            if match:
                return i
        return -1
    
    @staticmethod
    def parse_pattern(pattern_string: str) -> list:
        items = pattern_string.split()
        pattern = []
        for item in items:
            if item in ("?", "??"):
                pattern.append(None)
            else:
                pattern.append(int(item, 16))
        return pattern

@dataclass
class GameConfig:
    name: str
    process_names: list[str]
    world_chr_man_aob: str
    world_chr_man_jump_start: int
    world_chr_man_jump_end: int
    world_chr_man_struct_offset: int
    crash_patch_aob: str = None
    crash_patch_jump_end: int = None
    crash_patch_bytes: bytes = None
    shellcode_template: bytes = None
    shellcode_data_offset: int = 2
    shellcode_ptr_offset: int = 12

ELDEN_RING_CONFIGS = [
    GameConfig(
        name="Elden Ring 1.07+",
        process_names=["eldenring", "start_protected_game"],
        world_chr_man_aob="48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0F 48 39 88",
        world_chr_man_jump_start=3,
        world_chr_man_jump_end=7,
        world_chr_man_struct_offset=0x1E668,
        crash_patch_aob="80 65 ?? FD 48 C7 45 ?? 07 00 00 00 ?? 8D 45 48 4C 89 60 ?? 48 83 78 ?? 08 72 03 48 8B 00 66 44 89 20 49 8B 8F ?? ?? ?? ?? 48 8B 01 48 ?? ??",
        crash_patch_jump_end=3,
        crash_patch_bytes=b"\x48\x31\xd2",
        shellcode_template=bytes([
            0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x91, 0x68, 0xE6, 0x01, 0x00,
            0x48, 0x89, 0x1A, 0x48, 0x89, 0x13,
            0x48, 0x8B, 0x91, 0x68, 0xE6, 0x01, 0x00,
            0x48, 0x89, 0x5A, 0x08, 0x48, 0x89, 0x53, 0x08,
            0xC7, 0x81, 0x70, 0xE6, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xC7, 0x81, 0x78, 0xE6, 0x01, 0x00, 0x00, 0x00, 0x20, 0x41,
            0xC3,
        ])
    ),
    GameConfig(
        name="Elden Ring 1.06",
        process_names=["eldenring", "start_protected_game"],
        world_chr_man_aob="48 8B 05 ?? ?? ?? ?? 48 85 C0 74 0F 48 39 88",
        world_chr_man_jump_start=3,
        world_chr_man_jump_end=7,
        world_chr_man_struct_offset=0x185C0,
        crash_patch_aob="80 65 ?? FD 48 C7 45 ?? 07 00 00 00 ?? 8D 45 48 4C 89 60 ?? 48 83 78 ?? 08 72 03 48 8B 00 66 44 89 20 49 8B 8F ?? ?? ?? ?? 48 8B 01 48 ?? ??",
        crash_patch_jump_end=3,
        crash_patch_bytes=b"\x48\x31\xd2",
        shellcode_template=bytes([
            0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x91, 0xC0, 0x85, 0x01, 0x00,
            0x48, 0x89, 0x1A, 0x48, 0x89, 0x13,
            0x48, 0x8B, 0x91, 0xC0, 0x85, 0x01, 0x00,
            0x48, 0x89, 0x5A, 0x08, 0x48, 0x89, 0x53, 0x08,
            0xC7, 0x81, 0xC8, 0x85, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xC7, 0x81, 0xD0, 0x85, 0x01, 0x00, 0x00, 0x00, 0x20, 0x41,
            0xC3,
        ])
    )
]

class EldenRingReloader:
    def __init__(self):
        self.process_handle = None
        self.world_chr_man_ptr = 0
        self.current_config = None
        self.reload_count = 0
        self._connected = False
        self.monitoring_file = False
        self.monitor_thread = None
        self.last_modified = 0
        self.current_file = None
        self.game_monitor_running = True
        self.game_monitor_thread = None
        self.reloader_lock = threading.Lock()
    
    @property
    def connected(self):
        return self._connected and self.process_handle is not None and self.world_chr_man_ptr != 0
    
    def connect(self):
        with self.reloader_lock:
            if self.connected:
                return True
            
            if not PSUTIL_AVAILABLE:
                return False
            
            game_pid = None
            for proc in psutil.process_iter(['pid', 'name']):
                name = proc.info['name'].lower()
                if name in ['eldenring.exe', 'start_protected_game.exe']:
                    game_pid = proc.info['pid']
                    break
            
            if not game_pid:
                return False
            
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                False, game_pid
            )
            
            if not handle:
                return False
            
            base_address = 0x140000000
            try:
                proc = psutil.Process(game_pid)
                for mmap in proc.memory_maps(grouped=False):
                    if 'eldenring' in mmap.path.lower():
                        addr_parts = mmap.addr.split('-')
                        base_address = int(addr_parts[0], 16)
                        break
            except:
                pass
            
            world_chr_man_ptr = 0
            selected_config = None
            
            for config in ELDEN_RING_CONFIGS:
                try:
                    scanner = AOBScanner(handle, base_address, 0x10000000)
                    pattern = AOBScanner.parse_pattern(config.world_chr_man_aob)
                    address = scanner.scan(pattern)
                    
                    if address:
                        offset_addr = address + config.world_chr_man_jump_start
                        relative_offset = MemoryOperations.read_uint32(handle, offset_addr)
                        next_instruction = address + config.world_chr_man_jump_end
                        pointer_addr = next_instruction + relative_offset
                        
                        ptr = MemoryOperations.read_int64(handle, pointer_addr)
                        
                        if ptr and ptr > 0x10000:
                            world_chr_man_ptr = ptr
                            selected_config = config
                            
                            if config.crash_patch_aob:
                                crash_pattern = AOBScanner.parse_pattern(config.crash_patch_aob)
                                crash_location = scanner.scan(crash_pattern)
                                if crash_location:
                                    crash_fix_ptr = crash_location + len(crash_pattern) - config.crash_patch_jump_end
                                    MemoryOperations.write_bytes(handle, crash_fix_ptr, config.crash_patch_bytes)
                            break
                except:
                    continue
            
            if world_chr_man_ptr and selected_config:
                if self.process_handle:
                    kernel32.CloseHandle(self.process_handle)
                
                self.process_handle = handle
                self.world_chr_man_ptr = world_chr_man_ptr
                self.current_config = selected_config
                self._connected = True
                return True
            else:
                kernel32.CloseHandle(handle)
                return False
    
    def disconnect(self):
        with self.reloader_lock:
            if self.process_handle:
                kernel32.CloseHandle(self.process_handle)
                self.process_handle = None
            self.world_chr_man_ptr = 0
            self._connected = False
    
    def reload_character(self, chr_name="c0000"):
        with self.reloader_lock:
            if not self.connected:
                if not self.connect():
                    return False
            
            try:
                chr_name_bytes = chr_name.encode("utf-16-le") + b"\x00\x00"
                
                shellcode_addr = MemoryOperations.allocate_memory(self.process_handle, 256, PAGE_EXECUTE_READWRITE)
                data_setup_addr = MemoryOperations.allocate_memory(self.process_handle, 256, PAGE_READWRITE)
                
                if not shellcode_addr or not data_setup_addr:
                    return False
                
                data_pointer_addr = self.world_chr_man_ptr + self.current_config.world_chr_man_struct_offset
                first_level_ptr = MemoryOperations.read_int64(self.process_handle, data_pointer_addr)
                if not first_level_ptr:
                    MemoryOperations.free_memory(self.process_handle, shellcode_addr, 256)
                    MemoryOperations.free_memory(self.process_handle, data_setup_addr, 256)
                    return False
                
                data_pointer = MemoryOperations.read_int64(self.process_handle, first_level_ptr)
                if not data_pointer:
                    MemoryOperations.free_memory(self.process_handle, shellcode_addr, 256)
                    MemoryOperations.free_memory(self.process_handle, data_setup_addr, 256)
                    return False
                
                MemoryOperations.write_int64(self.process_handle, data_setup_addr + 0x8, data_pointer)
                MemoryOperations.write_int64(self.process_handle, data_setup_addr + 0x58, data_setup_addr + 0x100)
                MemoryOperations.write_int8(self.process_handle, data_setup_addr + 0x70, 0x1F)
                MemoryOperations.write_bytes(self.process_handle, data_setup_addr + 0x100, chr_name_bytes)
                
                shellcode = bytearray(self.current_config.shellcode_template)
                
                data_setup_bytes = struct.pack("<Q", data_setup_addr & 0xFFFFFFFFFFFFFFFF)
                offset = self.current_config.shellcode_data_offset
                shellcode[offset:offset + 8] = data_setup_bytes
                
                world_chr_man_bytes = struct.pack("<Q", self.world_chr_man_ptr & 0xFFFFFFFFFFFFFFFF)
                offset = self.current_config.shellcode_ptr_offset
                shellcode[offset:offset + 8] = world_chr_man_bytes
                
                MemoryOperations.write_bytes(self.process_handle, shellcode_addr, bytes(shellcode))
                
                thread_handle = MemoryOperations.create_remote_thread(self.process_handle, shellcode_addr)
                if thread_handle:
                    MemoryOperations.wait_for_thread(thread_handle)
                    MemoryOperations.close_handle(thread_handle)
                    self.reload_count += 1
                
                MemoryOperations.free_memory(self.process_handle, shellcode_addr, 256)
                MemoryOperations.free_memory(self.process_handle, data_setup_addr, 256)
                
                return True
                
            except Exception as e:
                print(f"Erro no reload: {e}")
                return False
    
    def start_file_monitoring(self, file_path):
        self.current_file = file_path
        self.monitoring_file = True
        if os.path.exists(file_path):
            self.last_modified = os.path.getmtime(file_path)
        
        if self.monitor_thread and self.monitor_thread.is_alive():
            return
        
        def monitor():
            while self.monitoring_file:
                try:
                    if self.current_file and os.path.exists(self.current_file):
                        current_mtime = os.path.getmtime(self.current_file)
                        if current_mtime > self.last_modified:
                            self.last_modified = current_mtime
                            time.sleep(0.2)
                            if self.connected:
                                self.reload_character()
                except:
                    pass
                time.sleep(1)
        
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
    
    def stop_file_monitoring(self):
        self.monitoring_file = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
    
    def start_game_monitoring(self, status_callback=None):
        self.game_monitor_running = True
        
        def monitor():
            last_connected = False
            while self.game_monitor_running:
                try:
                    game_running = False
                    if PSUTIL_AVAILABLE:
                        for proc in psutil.process_iter(['name']):
                            name = proc.info['name'].lower()
                            if name in ['eldenring.exe', 'start_protected_game.exe']:
                                game_running = True
                                break
                    
                    if game_running and not self.connected:
                        self.connect()
                    elif not game_running and self.connected:
                        self.disconnect()
                    
                    current_connected = self.connected
                    if current_connected != last_connected and status_callback:
                        status_callback(current_connected)
                    last_connected = current_connected
                    
                except Exception as e:
                    print(f"Erro no monitoramento: {e}")
                time.sleep(2)
        
        self.game_monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.game_monitor_thread.start()
    
    def stop_game_monitoring(self):
        self.game_monitor_running = False
        if self.game_monitor_thread:
            self.game_monitor_thread.join(timeout=2)

elden_reloader = EldenRingReloader()

class ModernCombobox(ttk.Combobox):
    def __init__(self, parent, **kwargs):
        style = ttk.Style()
        style.configure('Modern.TCombobox',
                       fieldbackground='#252525',
                       background='#252525',
                       foreground='#ffffff',
                       arrowcolor='#a0a0a0',
                       bordercolor='#404040',
                       lightcolor='#404040',
                       darkcolor='#404040',
                       borderwidth=1,
                       relief='flat')
        
        style.map('Modern.TCombobox',
                 fieldbackground=[('readonly', '#252525'),
                                 ('focus', '#303030')],
                 background=[('readonly', '#252525'),
                            ('focus', '#303030')],
                 arrowcolor=[('active', '#ffffff')])
        
        style.configure('Modern.TCombobox.Listbox',
                       background='#1a1a1a',
                       foreground='#ffffff',
                       bordercolor='#404040',
                       selectbackground='#007acc',
                       selectforeground='#ffffff',
                       font=('Segoe UI', 9))
        
        kwargs['style'] = 'Modern.TCombobox'
        super().__init__(parent, **kwargs)
        self.configure_state()
        self.bind('<Enter>', self.on_enter)
        self.bind('<Leave>', self.on_leave)
        
    def configure_state(self):
        try:
            self.tk.eval(f'''
                [ttk::combobox::PopdownWindow {self}]::listbox configure \
                -background #1a1a1a \
                -foreground #ffffff \
                -selectbackground #007acc \
                -selectforeground #ffffff \
                -font {{Segoe UI 9}} \
                -borderwidth 0 \
                -highlightthickness 0 \
                -relief flat
            ''')
        except:
            pass
    
    def on_enter(self, event):
        self.state(['active'])
    
    def on_leave(self, event):
        self.state(['!active'])

class LuaVariableParser:
    def __init__(self):
        self.variables = {}
        
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        try:
            encodings = ['utf-8', 'latin-1', 'cp1252', 'utf-16']
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding) as file:
                        content = file.read()
                    return self.parse_content(content)
                except UnicodeDecodeError:
                    continue
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
            return self.parse_content(content)
            
        except Exception as e:
            raise Exception(f"Erro ao ler arquivo: {e}")
    
    def parse_content(self, content: str) -> Dict[str, Any]:
        read_section_match = re.search(
            r'--// READ VARIABLES\s*(.*?)\s*--// END READ VARIABLES',
            content, 
            re.DOTALL | re.IGNORECASE
        )
        
        if not read_section_match:
            return {}
        
        read_section = read_section_match.group(1)
        
        variables = {}
        current_section = "Geral"
        current_ui_metadata = {}
        
        lines = read_section.split('\n')
        i = 0
        
        while i < len(lines):
            line = lines[i].strip()
            
            section_match = re.match(r'----+\s*(.+?)\s*----+', line)
            if section_match:
                current_section = section_match.group(1).strip()
                i += 1
                continue
            
            meta_type, meta_subtype, meta_value = self._parse_metadata_line(line)
            if meta_type:
                full_key = meta_type
                if meta_subtype:
                    full_key = f"{meta_type}_{meta_subtype}"
                
                if meta_type == 'HINT' and 'HINT' in current_ui_metadata:
                    current_ui_metadata['HINT'] += '\n' + meta_value
                elif meta_type == 'TAG':
                    if meta_subtype == 'COLOR':
                        if '_' in line:
                            color_parts = full_key.split('_')
                            if len(color_parts) > 2:
                                color_name = color_parts[2]
                                current_ui_metadata[f'TAG_COLOR_{color_name.upper()}'] = meta_value
                        else:
                            current_ui_metadata['TAG_COLOR'] = meta_value
                    else:
                        current_ui_metadata[full_key] = meta_value
                else:
                    current_ui_metadata[full_key] = meta_value
                i += 1
                continue
            
            var_match = None
            if line.startswith('local '):
                var_match = re.match(r'local\s+([a-zA-Z_]\w*)\s*=\s*(.+)', line)
            else:
                if line and not line.startswith('--') and '=' in line:
                    var_match = re.match(r'([a-zA-Z_]\w*)\s*=\s*(.+)', line)
            
            if var_match:
                var_name = var_match.group(1)
                var_value_str = var_match.group(2).split('--')[0].strip()
                
                has_selector = 'SELECTOR' in current_ui_metadata
                
                if var_value_str.startswith('{'):
                    table_content = self._extract_table_content(lines, i)
                    if table_content:
                        var_type = 'table'
                        processed_value = table_content['table_dict']
                        table_fields = self._extract_table_fields_metadata(lines, i)
                        i = table_content['end_index']
                    else:
                        var_type, processed_value = self._determine_type(var_value_str, has_selector)
                        table_fields = {}
                else:
                    var_type, processed_value = self._determine_type(var_value_str, has_selector)
                    table_fields = {}
                
                ui_data = self._process_ui_metadata(current_ui_metadata, var_name, var_type)
                
                if table_fields:
                    ui_data['table_fields'].update(table_fields)
                
                variables[var_name] = {
                    'value': processed_value,
                    'type': var_type,
                    'section': current_section,
                    'raw_value': var_value_str,
                    'ui_name': ui_data['name'],
                    'ui_hint': ui_data['hint'],
                    'ui_tags': ui_data['tags'],
                    'ui_tag_colors': ui_data['tag_colors'],
                    'ui_selector': ui_data['selector'],
                    'table_fields': ui_data.get('table_fields', {})
                }
                
                current_ui_metadata = {}
            
            i += 1
        
        return variables
    
    def _parse_metadata_line(self, line: str) -> Tuple[str, str, str]:
        pattern = r'--\s*\[UI\]\s*(\w+)(?:_(\w+))?\s*:\s*(.+)'
        match = re.match(pattern, line)
        if match:
            return match.group(1).upper(), match.group(2), match.group(3).strip()
        return None, None, None
    
    def _extract_table_fields_metadata(self, lines: List[str], start_index: int) -> Dict[str, Dict]:
        table_fields = {}
        i = start_index
        
        while i < len(lines):
            line = lines[i]
            if '{' in line:
                break
            i += 1
        
        if i >= len(lines):
            return table_fields
        
        i += 1
        brace_count = 1
        current_metadata = {}
        
        while i < len(lines) and brace_count > 0:
            line = lines[i].strip()
            
            if line.startswith('--') and '[UI] TABLEFIELD' in line.upper():
                metadata_match = re.match(r'--\s*\[UI\]\s*TABLEFIELD_(\w+):\s*(.+)', line, re.IGNORECASE)
                if metadata_match:
                    metadata_type = metadata_match.group(1).upper()
                    metadata_value = metadata_match.group(2).strip()
                    
                    if metadata_type == 'NAME':
                        current_metadata['name'] = metadata_value
                    elif metadata_type == 'HINT':
                        if 'hint' in current_metadata:
                            current_metadata['hint'] += '\n' + metadata_value
                        else:
                            current_metadata['hint'] = metadata_value
                    elif metadata_type == 'SELECTOR':
                        current_metadata['selector'] = metadataValue
            
            elif '=' in line and not line.startswith('--'):
                field_match = re.match(r'(\w+)\s*=', line)
                if field_match:
                    field_name = field_match.group(1)
                    
                    if current_metadata:
                        table_fields[field_name] = current_metadata
                        current_metadata = {}
            
            brace_count += line.count('{') - line.count('}')
            i += 1
        
        return table_fields
    
    def _extract_table_content(self, lines: List[str], start_index: int) -> Dict[str, Any]:
        start_line_index = start_index
        start_line = lines[start_index]
        
        brace_pos = start_line.find('{')
        if brace_pos == -1:
            return None
            
        table_content = start_line[brace_pos:]
        
        i = start_index
        brace_count = table_content.count('{') - table_content.count('}')
        
        original_lines = [start_line[brace_pos:]] if brace_count > 0 else []
        
        if brace_count <= 0:
            table_text = table_content
        else:
            i += 1
            while i < len(lines) and brace_count > 0:
                line = lines[i]
                table_content += '\n' + line
                original_lines.append(line)
                brace_count += line.count('{') - line.count('}')
                i += 1
            
            table_text = table_content
        
        try:
            table_dict = self._parse_lua_table_with_comments(original_lines)
            return {
                'table_dict': table_dict,
                'end_index': i - 1,
                'original_lines': original_lines
            }
        except Exception:
            return None

    def _parse_lua_table_with_comments(self, original_lines: List[str]) -> Dict[str, Any]:
        table_dict = {}
        
        full_text = '\n'.join(original_lines)
        
        clean_text = full_text.strip()
        if clean_text.startswith('{'):
            clean_text = clean_text[1:].strip()
        if clean_text.endswith('}'):
            clean_text = clean_text[:-1].strip()
        
        if not clean_text:
            return table_dict
        
        for line in original_lines:
            line = line.strip()
            if not line:
                continue
                
            if line.startswith('--'):
                continue
            
            if '=' in line:
                field_match = re.match(r'(\w+)\s*=\s*(.+)$', line.split('--')[0].strip())
                if field_match:
                    field_name = field_match.group(1)
                    value_str = field_match.group(2).split('--')[0].strip().rstrip(',')
                    
                    value = self._parse_lua_value(value_str)
                    table_dict[field_name] = value
        
        return table_dict

    def _parse_lua_table(self, table_text: str) -> Dict[str, Any]:
        table_dict = {}
        
        clean_text = table_text.strip()
        if clean_text.startswith('{'):
            clean_text = clean_text[1:].strip()
        if clean_text.endswith('}'):
            clean_text = clean_text[:-1].strip()
        
        clean_text = re.sub(r'--.*', '', clean_text)
        clean_text = clean_text.strip()
        
        if not clean_text:
            return table_dict
        
        entries = []
        current = ""
        in_string = False
        string_char = None
        brace_count = 0
        bracket_count = 0
        
        for char in clean_text:
            if char in ['"', "'"] and not in_string and brace_count == 0 and bracket_count == 0:
                in_string = True
                string_char = char
                current += char
            elif char == string_char and in_string and brace_count == 0 and bracket_count == 0:
                in_string = False
                string_char = None
                current += char
            elif char == '{' and not in_string:
                brace_count += 1
                current += char
            elif char == '}' and not in_string and brace_count > 0:
                brace_count -= 1
                current += char
            elif char == '[' and not in_string:
                bracket_count += 1
                current += char
            elif char == ']' and not in_string and bracket_count > 0:
                bracket_count -= 1
                current += char
            elif char == ',' and not in_string and brace_count == 0 and bracket_count == 0:
                if current.strip():
                    entries.append(current.strip())
                current = ""
            else:
                current += char
        
        if current.strip():
            entries.append(current.strip())
        
        for entry in entries:
            entry = entry.strip().rstrip(',')
            if not entry:
                continue
            
            match = re.match(r'(\w+|\[[^\]]+\])\s*=\s*(.+)', entry)
            if match:
                key = match.group(1)
                value_str = match.group(2).strip()
                
                if key.startswith('[') and key.endswith(']'):
                    key = key[1:-1].strip()
                    if (key.startswith('"') and key.endswith('"')) or (key.startswith("'") and key.endswith("'")):
                        key = key[1:-1]
                
                value = self._parse_lua_value(value_str)
                table_dict[key] = value
        
        return table_dict
    
    def _parse_lua_value(self, value_str: str) -> Any:
        value_str = value_str.strip().rstrip(',')
        
        if value_str.startswith('{'):
            open_braces = value_str.count('{')
            close_braces = value_str.count('}')
            if open_braces == close_braces:
                return self._parse_lua_table(value_str)
            else:
                return value_str
        
        if value_str.lower() == 'true':
            return True
        elif value_str.lower() == 'false':
            return False
        
        if re.match(r'^-?\d+$', value_str):
            return int(value_str)
        
        if re.match(r'^-?\d+\.\d+$', value_str):
            return float(value_str)
        
        if (value_str.startswith('"') and value_str.endswith('"')) or \
           (value_str.startswith("'") and value_str.endswith("'")):
            return value_str[1:-1]
        
        return value_str
    
    def _process_ui_metadata(self, ui_metadata: Dict, var_name: str, var_type: str) -> Dict:
        name = ui_metadata.get('NAME', var_name.replace('_', ' ').title())
        hint = ui_metadata.get('HINT', '')
        selector_raw = ui_metadata.get('SELECTOR', '')
        
        tags = []
        tag_colors = {}
        
        for key, value in ui_metadata.items():
            if key == 'TAG':
                tag_list = [t.strip() for t in value.split(',') if t.strip()]
                tags.extend(tag_list)
            elif key.startswith('TAG') and key != 'TAG_COLOR' and not key.startswith('TAG_COLOR_'):
                tag_list = [t.strip() for t in value.split(',') if t.strip()]
                tags.extend(tag_list)
        
        for key, value in ui_metadata.items():
            if key.startswith('TAG_COLOR'):
                if '_' in key and key != 'TAG_COLOR':
                    color_parts = key.split('_')
                    if len(color_parts) > 2:
                        color_name = color_parts[2].upper()
                        tag_colors[color_name] = value.strip()
                elif key == 'TAG_COLOR':
                    if len(tags) == 1:
                        tag_colors[tags[0].upper()] = value.strip()
                    else:
                        tag_colors['DEFAULT'] = value.strip()
        
        for i, tag in enumerate(tags):
            tag_upper = tag.upper()
            
            if tag_upper in tag_colors:
                continue
            
            if tag_upper in ['RED', 'GREEN', 'BLUE', 'YELLOW', 'ORANGE', 
                            'PURPLE', 'CYAN', 'PINK', 'GRAY', 'WHITE', 'BLACK']:
                tag_colors[tag_upper] = tag_upper
            elif 'DEFAULT' not in tag_colors:
                if any(word in tag_upper for word in ['UNSUPPORTED', 'DEPRECATED', 'ERROR']):
                    tag_colors[tag_upper] = 'RED'
                elif any(word in tag_upper for word in ['EXPERIMENTAL', 'WIP', 'BETA', 'ALPHA']):
                    tag_colors[tag_upper] = 'ORANGE'
                elif any(word in tag_upper for word in ['NEW', 'STABLE', 'SUPPORTED']):
                    tag_colors[tag_upper] = 'GREEN'
                elif any(word in tag_upper for word in ['LEGACY', 'OLD']):
                    tag_colors[tag_upper] = 'GRAY'
                else:
                    tag_colors[tag_upper] = 'BLUE'
        
        selector_options = {}
        if selector_raw:
            if selector_raw.strip():
                var_type = 'selector'
            selector_options = self._parse_selector(selector_raw, var_type)
        
        table_fields = {}
        if var_type == 'table':
            table_fields = self._parse_table_fields(ui_metadata)
        
        return {
            'name': name,
            'hint': hint,
            'tags': tags,
            'tag_colors': tag_colors,
            'selector': selector_options,
            'table_fields': table_fields
        }
    
    def _parse_table_fields(self, ui_metadata: Dict) -> Dict[str, Dict]:
        table_fields = {}
        
        for key, value in ui_metadata.items():
            if key.startswith('FIELD_'):
                field_name = key[6:]
                field_parts = value.split('|')
                
                if len(field_parts) >= 2:
                    field_display_name = field_parts[0].strip()
                    field_hint = field_parts[1].strip() if len(field_parts) > 1 else ""
                    field_selector = field_parts[2].strip() if len(field_parts) > 2 else ""
                    
                    table_fields[field_name] = {
                        'name': field_display_name,
                        'hint': field_hint,
                        'selector': self._parse_selector(field_selector, 'string') if field_selector else {}
                    }
        
        return table_fields
    
    def _parse_selector(self, selector_text: str, var_type: str) -> Dict:
        options = {}
        
        selector_text = selector_text.strip()
        if not selector_text:
            return options
        
        parts = []
        current_part = ""
        in_quotes = False
        quote_char = None
        
        for char in selector_text:
            if char in ['"', "'"] and not in_quotes:
                in_quotes = True
                quote_char = char
                current_part += char
            elif char == quote_char and in_quotes:
                in_quotes = False
                quote_char = None
                current_part += char
            elif char == ',' and not in_quotes:
                if current_part.strip():
                    parts.append(current_part.strip())
                current_part = ""
            else:
                current_part += char
        
        if current_part.strip():
            parts.append(current_part.strip())
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
                
            if '=' in part:
                key_value_match = re.match(r'([^=]+?)\s*=\s*(.+)', part)
                if key_value_match:
                    key_str = key_value_match.group(1).strip()
                    value = key_value_match.group(2).strip()
                    
                    options[key_str] = value
            else:
                value = part.strip()
                options[value] = value
        
        return options
    
    def _determine_type(self, value: str, has_selector: bool = False) -> Tuple[str, Any]:
        value = value.strip().rstrip(',')
        
        if has_selector:
            return 'selector', value
        
        if value.lower() in ['true', 'false']:
            return 'boolean', value.lower() == 'true'
        
        if re.match(r'^-?\d+$', value):
            return 'integer', int(value)
        
        if re.match(r'^-?\d+\.\d+$', value):
            return 'float', float(value)
        
        if re.match(r'^[\'\"].*[\'\"]$', value):
            return 'string', value[1:-1]
        
        return 'string', value

class UltraCompactConfigurator:
    def __init__(self, root):
        self.root = root
        self.root.title("Lua Configurator")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0a0a0a')
        self.root.minsize(1200, 700)
        
        self.colors = {
            'bg': '#0a0a0a',
            'header_bg': '#1a1a1a',
            'surface': '#151515',
            'surface_light': '#202020',
            'accent': '#007acc',
            'accent_hover': '#0098ff',
            'text': '#ffffff',
            'text_secondary': '#a0a0a0',
            'text_muted': '#555555',
            'border': '#252525',
            'toggle_on': '#007acc',
            'toggle_off': '#252525',
            'type_badge': '#333333',
            'scrollbar_bg': '#1a1a1a',
            'scrollbar_slider': '#404040',
            'scrollbar_hover': '#505050',
            'table_header': '#2a2a2a',
            'section_header': '#2a2a2a',
            'add_button': '#00cc66',
            'add_button_hover': '#00ff88',
            'rescan_button': '#007acc',
            'rescan_button_hover': '#0098ff',
            'file_block_bg': '#1a1a1a',
            'file_block_hover': '#2a2a2a',
            'tag_red': '#ff4444',
            'tag_green': '#44ff44',
            'tag_blue': '#4444ff',
            'tag_yellow': '#ffff44',
            'tag_orange': '#ffa500',
            'tag_purple': '#aa44ff',
            'tag_cyan': '#44ffff',
            'tag_pink': '#ff44ff',
            'tag_gray': '#888888',
            'tag_default': '#444444',
            'tag_white': '#ffffff',
            'tag_black': '#000000',
        }
        
        self.tag_color_map = {
            'RED': 'tag_red',
            'GREEN': 'tag_green',
            'BLUE': 'tag_blue',
            'YELLOW': 'tag_yellow',
            'ORANGE': 'tag_orange',
            'PURPLE': 'tag_purple',
            'CYAN': 'tag_cyan',
            'PINK': 'tag_pink',
            'GRAY': 'tag_gray',
            'WHITE': 'tag_white',
            'BLACK': 'tag_black',
            'UNSUPPORTED': 'tag_red',
            'EXPERIMENTAL': 'tag_orange',
            'NEW': 'tag_green',
            'DEPRECATED': 'tag_yellow',
            'BETA': 'tag_purple',
            'ALPHA': 'tag_cyan',
            'WIP': 'tag_orange',
            'STABLE': 'tag_green',
            'LEGACY': 'tag_gray',
        }
        
        self.parser = LuaVariableParser()
        self.variables = {}
        self.controls = {}
        self.expanded_tables = set()
        self.table_content_frames = {}
        self.lua_file_path = None
        
        self.detected_files = []
        self.current_view = "files"
        
        self.normal_variables = {}
        self.table_variables = {}
        
        self.setup_styles()
        self.create_interface()
        
        self.game_status_label = None
        
        elden_reloader.start_game_monitoring(self.update_game_status)
        
        try:
            self.root.after(100, self.show_files_selection)
        except Exception:
            self.show_files_selection()
    
    def update_game_status(self, connected=None):
        if connected is None:
            connected = elden_reloader.connected
        
        if self.game_status_label and self.game_status_label.winfo_exists():
            if connected:
                self.game_status_label.config(text="🟢", fg='#44ff44')
            else:
                self.game_status_label.config(text="🔴", fg='#ff4444')
    
    def detect_files(self):
        self.detected_files = []
        
        search_paths = []
        seen_paths = set()
        
        current_dir = Path.cwd()
        search_paths.append(current_dir)
        
        possible_paths = [
            current_dir / "mod" / "action" / "script",
            current_dir / "mod" / "action" / "script" / "module",
            current_dir / "mod" / "script",
            current_dir / "action" / "script",
            current_dir / "script",
            current_dir / "module",
        ]
        
        for path in possible_paths:
            if path.exists():
                search_paths.append(path)
        
        unique_paths = []
        for path in search_paths:
            if path not in unique_paths:
                unique_paths.append(path)
        
        search_paths = unique_paths
        
        for base_path in search_paths:
            for ext in ['*.lua', '*.hks']:
                try:
                    for file_path in base_path.rglob(ext):
                        if str(file_path) in seen_paths:
                            continue
                        
                        seen_paths.add(str(file_path))
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            has_read_vars = bool(re.search(r'--//\s*READ\s*VARIABLES', content, re.IGNORECASE))
                            
                            if has_read_vars:
                                try:
                                    variables = self.parser.parse_content(content)
                                    var_count = len(variables)
                                except Exception:
                                    var_count = 0
                                
                                absolute_path = file_path.absolute()
                                
                                try:
                                    relative_path = file_path.relative_to(current_dir)
                                except ValueError:
                                    relative_path = file_path
                                
                                file_info = {
                                    'path': str(absolute_path),
                                    'name': file_path.name,
                                    'folder': str(file_path.parent),
                                    'variables_count': var_count,
                                    'has_variables': var_count > 0,
                                    'relative_path': str(relative_path)
                                }
                                
                                self.detected_files.append(file_info)
                                
                        except Exception:
                            continue
                        
                except Exception:
                    continue
        
        self.detected_files.sort(key=lambda x: x['name'].lower())
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('.', 
                       background=self.colors['bg'],
                       foreground=self.colors['text'])
        
        style.configure('Primary.TButton',
                       background=self.colors['accent'],
                       foreground=self.colors['text'],
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 10, 'bold'),
                       padding=(20, 10))
        style.map('Primary.TButton',
                 background=[('active', self.colors['accent_hover']),
                           ('pressed', self.colors['accent_hover'])])
        
        style.configure('Secondary.TButton',
                       background=self.colors['surface_light'],
                       foreground=self.colors['text_secondary'],
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 9),
                       padding=(12, 6))
        style.map('Secondary.TButton',
                 background=[('active', self.colors['surface']),
                           ('pressed', self.colors['surface'])])
        
        style.configure('Expand.TButton',
                       background=self.colors['surface_light'],
                       foreground=self.colors['text_secondary'],
                       borderwidth=0,
                       focuscolor='none',
                       font=('Segoe UI', 8),
                       padding=(8, 4))
        style.map('Expand.TButton',
                 background=[('active', self.colors['accent']),
                           ('pressed', self.colors['accent_hover'])])
        
        style.configure('Compact.TEntry',
                       fieldbackground=self.colors['surface'],
                       foreground=self.colors['text'],
                       borderwidth=1,
                       relief='flat',
                       insertcolor=self.colors['text'],
                       padding=(8, 6))
        
        style.configure('Modern.TCombobox',
                       fieldbackground='#252525',
                       background='#252525',
                       foreground='#ffffff',
                       arrowcolor='#a0a0a0',
                       bordercolor='#404040',
                       lightcolor='#404040',
                       darkcolor='#404040',
                       borderwidth=1,
                       relief='flat',
                       padding=(8, 4))
        
        style.map('Modern.TCombobox',
                 fieldbackground=[('readonly', '#252525'),
                                 ('focus', '#303030')],
                 background=[('readonly', '#252525'),
                            ('focus', '#303030')],
                 arrowcolor=[('active', '#ffffff')])
        
        style.configure('Modern.TCombobox.Listbox',
                       background='#1a1a1a',
                       foreground='#ffffff',
                       bordercolor='#404040',
                       selectbackground='#007acc',
                       selectforeground='#ffffff',
                       font=('Segoe UI', 9))
    
    def create_interface(self):
        self.header_frame = tk.Frame(self.root, bg=self.colors['header_bg'], height=60)
        self.header_frame.pack(fill=tk.X, padx=0, pady=0)
        self.header_frame.pack_propagate(False)
        
        self.header_container = tk.Frame(self.header_frame, bg=self.colors['header_bg'], padx=20, pady=8)
        self.header_container.pack(fill=tk.BOTH, expand=True)
        
        self.create_header_content()
        
        self.content_container = tk.Frame(self.root, bg=self.colors['bg'])
        self.content_container.pack(fill=tk.BOTH, expand=True, padx=(12, 0), pady=(0, 0))
    
    def create_header_content(self):
        for widget in self.header_container.winfo_children():
            widget.destroy()
        
        main_row = tk.Frame(self.header_container, bg=self.colors['header_bg'])
        main_row.pack(fill=tk.X)
        
        title_frame = tk.Frame(main_row, bg=self.colors['header_bg'])
        title_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        title_label = tk.Label(title_frame,
                              text="LUA CONFIGURATOR",
                              font=('Segoe UI', 14, 'bold'),
                              bg=self.colors['header_bg'],
                              fg=self.colors['text'])
        title_label.pack(anchor='w')
        
        self.file_label = tk.Label(title_frame,
                                 text="No file loaded",
                                 font=('Segoe UI', 9),
                                 bg=self.colors['header_bg'],
                                 fg=self.colors['text_secondary'])
        self.file_label.pack(anchor='w', pady=(2, 0))
        
        actions_frame = tk.Frame(main_row, bg=self.colors['header_bg'])
        actions_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        if self.current_view == "config":
            self.game_status_label = tk.Label(actions_frame,
                                             text="🔴",
                                             font=('Segoe UI', 12, 'bold'),
                                             bg=self.colors['header_bg'],
                                             fg='#ff4444')
            self.game_status_label.pack(side=tk.LEFT, padx=(0, 10))
            self.update_game_status()
            
            back_btn = ttk.Button(actions_frame,
                                text="← Back to Files",
                                command=self.return_to_files_selection,
                                style='Secondary.TButton')
            back_btn.pack(side=tk.LEFT, padx=(0, 10))
            
            self.save_btn = ttk.Button(actions_frame,
                                     text="Save Changes", 
                                     command=self.save_changes,
                                     style='Primary.TButton')
            self.save_btn.pack(side=tk.RIGHT)
        else:
            load_btn = ttk.Button(actions_frame,
                                text="Load File",
                                command=self.add_new_file,
                                style='Secondary.TButton')
            load_btn.pack(side=tk.RIGHT, padx=(0, 1000000))
    
    def show_files_selection(self):
        self.current_view = "files"
        self.create_header_content()
        
        elden_reloader.stop_file_monitoring()
        
        for widget in self.content_container.winfo_children():
            widget.destroy()
        
        self.detect_files()
        
        main_frame = tk.Frame(self.content_container, bg=self.colors['bg'])
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        title_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        title_frame.pack(fill=tk.X, pady=(0, 30))
        
        title_label = tk.Label(title_frame,
                             text="SELECT FILE TO CONFIGURE",
                             font=('Segoe UI', 16, 'bold'),
                             bg=self.colors['bg'],
                             fg=self.colors['text'])
        title_label.pack(side=tk.LEFT)
        
        count_label = tk.Label(title_frame,
                             text=f"{len(self.detected_files)} files detected" if self.detected_files else "No files detected",
                             font=('Segoe UI', 11),
                             bg=self.colors['bg'],
                             fg=self.colors['text_secondary'])
        count_label.pack(side=tk.RIGHT)
        
        grid_frame = tk.Frame(main_frame, bg=self.colors['bg'])
        grid_frame.pack(fill=tk.BOTH, expand=True)
        
        row, col = 0, 0
        max_cols = 5
        
        add_block = self.create_add_file_block(grid_frame)
        add_block.grid(row=row, column=col, padx=15, pady=15, sticky='nsew')
        col += 1
        
        rescan_block = self.create_rescan_file_block(grid_frame)
        rescan_block.grid(row=row, column=col, padx=15, pady=15, sticky='nsew')
        col += 1
        
        if self.detected_files:
            for i, file_info in enumerate(self.detected_files):
                if col >= max_cols:
                    col = 0
                    row += 1
                
                block = self.create_file_block(grid_frame, file_info)
                block.grid(row=row, column=col, padx=15, pady=15, sticky='nsew')
                
                col += 1
        else:
            row += 1
            col = 0
            
            message_frame = tk.Frame(grid_frame, bg=self.colors['bg'])
            message_frame.grid(row=row, column=col, columnspan=max_cols, pady=(30, 0), sticky='nsew')
            
            empty_label = tk.Label(message_frame,
                                 text="No Lua/HKS files with READ VARIABLES found",
                                 font=('Segoe UI', 12, 'bold'),
                                 bg=self.colors['bg'],
                                 fg=self.colors['text_secondary'])
            empty_label.pack(pady=(0, 10))
            
            sub_label = tk.Label(message_frame,
                               text="Use '+' to add a file manually or 'Rescan Files' to search again",
                               font=('Segoe UI', 10),
                               bg=self.colors['bg'],
                               fg=self.colors['text_muted'])
            sub_label.pack()
        
        for i in range(max_cols):
            grid_frame.grid_columnconfigure(i, weight=1, uniform="col")
    
    def create_add_file_block(self, parent):
        block = tk.Frame(parent,
                        bg=self.colors['add_button'],
                        height=200,
                        cursor="hand2",
                        relief='flat',
                        highlightbackground=self.colors['add_button_hover'],
                        highlightthickness=2)
        
        content_frame = tk.Frame(block, bg=self.colors['add_button'])
        content_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        icon_label = tk.Label(content_frame,
                            text="+",
                            font=('Segoe UI', 48, 'bold'),
                            bg=self.colors['add_button'],
                            fg=self.colors['text'])
        icon_label.pack()
        
        text_label = tk.Label(content_frame,
                            text="Add File",
                            font=('Segoe UI', 12, 'bold'),
                            bg=self.colors['add_button'],
                            fg=self.colors['text'])
        text_label.pack(pady=(10, 0))
        
        block.bind("<Button-1>", lambda e: self.add_new_file())
        block.bind("<Enter>", lambda e: block.configure(bg=self.colors['add_button_hover']))
        block.bind("<Leave>", lambda e: block.configure(bg=self.colors['add_button']))
        
        for widget in [content_frame, icon_label, text_label]:
            widget.bind("<Enter>", lambda e: block.configure(bg=self.colors['add_button_hover']))
            widget.bind("<Leave>", lambda e: block.configure(bg=self.colors['add_button']))
            widget.bind("<Button-1>", lambda e: self.add_new_file())
        
        return block
    
    def create_rescan_file_block(self, parent):
        block = tk.Frame(parent,
                        bg=self.colors['rescan_button'],
                        height=200,
                        cursor="hand2",
                        relief='flat',
                        highlightbackground=self.colors['rescan_button_hover'],
                        highlightthickness=2)
        
        content_frame = tk.Frame(block, bg=self.colors['rescan_button'])
        content_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        icon_label = tk.Label(content_frame,
                            text="🔄",
                            font=('Segoe UI', 32, 'bold'),
                            bg=self.colors['rescan_button'],
                            fg=self.colors['text'])
        icon_label.pack(pady=(5, 0))
        
        text_label = tk.Label(content_frame,
                            text="Rescan Files",
                            font=('Segoe UI', 12, 'bold'),
                            bg=self.colors['rescan_button'],
                            fg=self.colors['text'])
        text_label.pack(pady=(10, 0))
        
        block.bind("<Button-1>", lambda e: self.rescan_files())
        block.bind("<Enter>", lambda e: block.configure(bg=self.colors['rescan_button_hover']))
        block.bind("<Leave>", lambda e: block.configure(bg=self.colors['rescan_button']))
        
        for widget in [content_frame, icon_label, text_label]:
            widget.bind("<Enter>", lambda e: block.configure(bg=self.colors['rescan_button_hover']))
            widget.bind("<Leave>", lambda e: block.configure(bg=self.colors['rescan_button']))
            widget.bind("<Button-1>", lambda e: self.rescan_files())
        
        return block
    
    def create_file_block(self, parent, file_info):
        block = tk.Frame(parent,
                        bg=self.colors['file_block_bg'],
                        height=200,
                        cursor="hand2",
                        relief='flat',
                        highlightbackground=self.colors['accent'],
                        highlightthickness=1)
        
        content_frame = tk.Frame(block, bg=self.colors['file_block_bg'], padx=15, pady=15)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        icon_label = tk.Label(content_frame,
                            text="📄",
                            font=('Segoe UI', 24),
                            bg=self.colors['file_block_bg'],
                            fg=self.colors['text'])
        icon_label.pack(anchor='w', pady=(0, 10))
        
        name_label = tk.Label(content_frame,
                            text=file_info['name'],
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['file_block_bg'],
                            fg=self.colors['text'],
                            wraplength=160,
                            justify=tk.LEFT)
        name_label.pack(fill=tk.X, pady=(0, 5))
        
        folder_text = file_info['relative_path']
        if len(folder_text) > 30:
            folder_text = "..." + folder_text[-27:]
        
        folder_label = tk.Label(content_frame,
                          text=folder_text,
                          font=('Segoe UI', 8),
                          bg=self.colors['file_block_bg'],
                          fg=self.colors['text_secondary'],
                          wraplength=160,
                          justify=tk.LEFT)
        folder_label.pack(fill=tk.X, pady=(0, 10))
        
        status_frame = tk.Frame(content_frame, bg=self.colors['file_block_bg'])
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        if file_info['has_variables']:
            status_text = f"{file_info['variables_count']} vars"
            status_color = self.colors['accent']
        else:
            status_text = "No variables"
            status_color = self.colors['text_muted']
        
        status_badge = tk.Label(status_frame,
                          text=status_text,
                          font=('Segoe UI', 7, 'bold'),
                          bg=status_color,
                          fg=self.colors['text'],
                          padx=6,
                          pady=2)
        status_badge.pack(side=tk.LEFT)
        
        def handle_click(event=None):
            self.load_file_from_selection(file_info)
        
        block.bind("<Button-1>", lambda e: handle_click())
        
        for widget in [content_frame, icon_label, name_label, folder_label, status_frame, status_badge]:
            widget.bind("<Button-1>", lambda e: handle_click())
        
        def on_enter(e):
            block.configure(bg=self.colors['file_block_hover'])
            for child_widget in [content_frame, icon_label, name_label, folder_label, status_frame, status_badge]:
                try:
                    child_widget.configure(bg=self.colors['file_block_hover'])
                except:
                    pass
        
        def on_leave(e):
            block.configure(bg=self.colors['file_block_bg'])
            for child_widget in [content_frame, icon_label, name_label, folder_label, status_frame, status_badge]:
                try:
                    child_widget.configure(bg=self.colors['file_block_bg'])
                except:
                    pass
        
        block.bind("<Enter>", on_enter)
        block.bind("<Leave>", on_leave)
        
        for widget in [content_frame, icon_label, name_label, folder_label, status_frame, status_badge]:
            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)
        
        return block
    
    def create_tag_badge(self, parent, tag_name: str, tag_color: str = None):
        normalized_tag = tag_name.upper().strip()
        
        if tag_color:
            normalized_color = tag_color.upper().strip()
            color_key = self.tag_color_map.get(normalized_color, f'tag_{normalized_color.lower()}')
        else:
            if normalized_tag in self.tag_color_map:
                color_key = self.tag_color_map[normalized_tag]
            else:
                first_word = normalized_tag.split()[0] if ' ' in normalized_tag else normalized_tag
                color_key = self.tag_color_map.get(first_word, 'tag_default')
        
        if color_key not in self.colors:
            color_key = 'tag_default'
        
        bg_color = self.colors[color_key]
        
        try:
            if color_key in ['tag_yellow', 'tag_cyan', 'tag_gray', 'tag_default', 'tag_white']:
                text_color = '#000000'
            else:
                text_color = '#ffffff'
        except:
            text_color = '#ffffff'
        
        tag_frame = tk.Frame(parent, bg=bg_color, padx=6, pady=2)
        
        tag_label = tk.Label(tag_frame,
                        text=tag_name.upper(),
                        font=('Segoe UI', 6, 'bold'),
                        bg=bg_color,
                        fg=text_color,
                        padx=1,
                        pady=0)
        tag_label.pack()
        
        return tag_frame
    
    def load_file_from_selection(self, file_info):
        file_path = Path(file_info['path'])
        
        if not file_path.exists():
            current_dir = Path.cwd()
            
            search_locations = [
                current_dir / file_info['name'],
                current_dir / "mod" / "action" / "script" / file_info['name'],
                current_dir / "mod" / "action" / "script" / "module" / file_info['name'],
                current_dir / "script" / file_info['name'],
                current_dir / "action" / "script" / file_info['name'],
                current_dir / file_info.get('relative_path', ''),
            ]
            
            if 'folder' in file_info:
                folder_path = Path(file_info['folder'])
                if folder_path.exists():
                    search_locations.append(folder_path / file_info['name'])
            
            search_locations = list(dict.fromkeys(search_locations))
            
            found = False
            for location in search_locations:
                if location.exists():
                    file_path = location
                    found = True
                    break
            
            if not found:
                response = messagebox.askyesno("File Not Found", 
                                             f"Could not find file: {file_info['name']}\n\n"
                                             f"Do you want to locate it manually?")
                if response:
                    new_path = filedialog.askopenfilename(
                        title=f"Locate {file_info['name']}",
                        filetypes=[("Lua files", "*.lua"), ("HKS files", "*.hks"), ("All files", "*.*")],
                        initialdir=current_dir
                    )
                    if new_path:
                        file_path = Path(new_path)
                        if not file_path.exists():
                            messagebox.showerror("Error", "Selected file does not exist!")
                            return
                    else:
                        return
                else:
                    messagebox.showerror("Error", f"File not found:\n{file_info['path']}")
                    return
        
        try:
            variables = self.parser.parse_file(str(file_path))
            
            if variables:
                self.variables = variables
                self.lua_file_path = str(file_path)
                
                self.file_label.config(text=f"Editing: {file_info['name']}")
                
                self.show_config_interface()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file:\n{str(e)}\n\nPath: {file_path}")
    
    def show_config_interface(self):
        self.current_view = "config"
        self.create_header_content()
        
        if self.lua_file_path:
            elden_reloader.start_file_monitoring(self.lua_file_path)
        
        for widget in self.content_container.winfo_children():
            widget.destroy()
        
        content_frame = tk.Frame(self.content_container, bg=self.colors['bg'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=(0, 0), pady=(0, 0))
        
        self.canvas = tk.Canvas(content_frame, bg=self.colors['bg'], 
                               highlightthickness=0, bd=0, relief='flat')
        
        self.scrollable_frame = tk.Frame(self.canvas, bg=self.colors['bg'])
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw", width=1380)
        
        self.scrollbar_frame = self.create_modern_scrollbar(content_frame)
        
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        def on_mousewheel(event):
            self.canvas.yview_scroll(int(-event.delta / 60), "units")
            self.update_slider_position()
            return "break"
        
        self.canvas.bind("<MouseWheel>", on_mousewheel)
        self.root.bind_all("<MouseWheel>", on_mousewheel)
        
        self.create_variable_controls()
        
        self.canvas.update_idletasks()
        self.update_slider_position()
    
    def create_modern_scrollbar(self, parent):
        scroll_frame = tk.Frame(parent, bg=self.colors['scrollbar_bg'], width=8)
        scroll_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 0))
        scroll_frame.pack_propagate(False)
        
        self.slider = tk.Frame(scroll_frame, bg=self.colors['scrollbar_slider'], 
                              width=4, height=100, cursor="hand2")
        self.slider.place(relx=0.5, rely=0, anchor='n')
        
        self.is_dragging = False
        self.drag_start_y = 0
        self.slider_start_y = 0
        
        def start_drag(event):
            self.is_dragging = True
            self.drag_start_y = event.y_root
            self.slider_start_y = self.slider.winfo_y()
            self.slider.configure(bg=self.colors['scrollbar_hover'])
        
        def do_drag(event):
            if not self.is_dragging:
                return
                
            delta = event.y_root - self.drag_start_y
            new_y = self.slider_start_y + delta
            
            slider_height = self.slider.winfo_height()
            scroll_height = scroll_frame.winfo_height()
            max_y = scroll_height - slider_height
            
            if new_y < 0:
                new_y = 0
            elif new_y > max_y:
                new_y = max_y
                
            self.slider.place(y=new_y)
            
            if max_y > 0:
                scroll_ratio = new_y / max_y
                content_height = self.scrollable_frame.winfo_height()
                visible_height = self.canvas.winfo_height()
                max_scroll = max(content_height - visible_height, 1)
                scroll_pos = scroll_ratio * max_scroll
                self.canvas.yview_moveto(scroll_pos / content_height)
        
        def end_drag(event):
            self.is_dragging = False
            self.slider.configure(bg=self.colors['scrollbar_slider'])
        
        def on_mousewheel(event):
            scroll_amount = -int(event.delta / 60)
            self.canvas.yview_scroll(scroll_amount, "units")
            self.update_slider_position()
        
        self.slider.bind("<ButtonPress-1>", start_drag)
        self.slider.bind("<B1-Motion>", do_drag)
        self.slider.bind("<ButtonRelease-1>", end_drag)
        scroll_frame.bind("<MouseWheel>", on_mousewheel)
        self.slider.bind("<MouseWheel>", on_mousewheel)
        
        def on_canvas_configure(event):
            self.update_slider_position()
        
        self.canvas.bind("<Configure>", on_canvas_configure)
        
        return scroll_frame
    
    def update_slider_position(self):
        if not hasattr(self, 'slider'):
            return
            
        first_visible, last_visible = self.canvas.yview()
        scroll_ratio = first_visible
        
        scroll_frame = self.slider.master
        scroll_height = scroll_frame.winfo_height()
        
        content_height = self.scrollable_frame.winfo_height()
        visible_height = self.canvas.winfo_height()
        
        if content_height > 0:
            visible_ratio = visible_height / content_height
            slider_height = max(30, scroll_height * visible_ratio)
        else:
            slider_height = scroll_height
            
        self.slider.configure(height=slider_height)
        
        max_y = scroll_height - slider_height
        new_y = scroll_ratio * max_y
        
        self.slider.place(y=new_y)
    
    def return_to_files_selection(self):
        self.variables = {}
        self.controls = {}
        self.lua_file_path = None
        self.expanded_tables.clear()
        self.table_content_frames = {}
        
        elden_reloader.stop_file_monitoring()
        
        self.show_files_selection()
    
    def add_new_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Lua/HKS File",
            filetypes=[
                ("Lua files", "*.lua"),
                ("HKS files", "*.hks"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                response = True
                if not re.search(r'--//\s*READ\s*VARIABLES', content, re.IGNORECASE):
                    response = messagebox.askyesno("Warning", 
                                                 "File doesn't contain READ VARIABLES section.\n"
                                                 "Do you want to load it anyway?")
                
                if response:
                    self.load_file_from_selection({
                        'path': file_path,
                        'name': Path(file_path).name
                    })
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file:\n{str(e)}")
    
    def rescan_files(self):
        self.detect_files()
        self.show_files_selection()
        
        if self.detected_files:
            messagebox.showinfo("Rescan Complete", 
                              f"Found {len(self.detected_files)} Lua/HKS files with READ VARIABLES")
        else:
            messagebox.showinfo("Rescan Complete", 
                              "No Lua/HKS files with READ VARIABLES found")
    
    def create_variable_controls(self):
        if hasattr(self, 'scrollable_frame'):
            for widget in self.scrollable_frame.winfo_children():
                widget.destroy()
        else:
            return
        
        self.table_content_frames = {}
        
        if not self.variables:
            self.show_empty_state()
            return
        
        self.normal_variables = {}
        self.table_variables = {}
        
        for var_name, var_data in self.variables.items():
            if var_data['type'] == 'table':
                self.table_variables[var_name] = var_data
            else:
                self.normal_variables[var_name] = var_data
        
        self.create_main_layout()
    
    def create_main_layout(self):
        main_container = tk.Frame(self.scrollable_frame, bg=self.colors['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        
        if self.normal_variables:
            normal_section = tk.Frame(main_container, bg=self.colors['bg'])
            normal_section.pack(fill=tk.X, pady=(0, 15))
            
            normal_grid = tk.Frame(normal_section, bg=self.colors['bg'])
            normal_grid.pack(fill=tk.X)
            
            self.create_variables_grid(normal_grid, list(self.normal_variables.items()))
        
        if self.table_variables:
            tables_section = tk.Frame(main_container, bg=self.colors['bg'])
            tables_section.pack(fill=tk.X)
            
            section_header = tk.Frame(tables_section, bg=self.colors['section_header'], height=30)
            section_header.pack(fill=tk.X, pady=(0, 12))
            section_header.pack_propagate(False)
            
            section_label = tk.Label(section_header,
                                   text="TABLES",
                                   font=('Segoe UI', 11, 'bold'),
                                   bg=self.colors['section_header'],
                                   fg=self.colors['text_secondary'],
                                   padx=15)
            section_label.pack(side=tk.LEFT, fill=tk.Y)
            
            count_label = tk.Label(section_header,
                                 text=f"{len(self.table_variables)} tables",
                                 font=('Segoe UI', 9),
                                 bg=self.colors['section_header'],
                                 fg=self.colors['text_muted'],
                                 padx=15)
            count_label.pack(side=tk.RIGHT, fill=tk.Y)
            
            self.create_tables_grid(tables_section, list(self.table_variables.items()))
    
    def create_variables_grid(self, parent, variables: List):
        grid_container = tk.Frame(parent, bg=self.colors['bg'])
        grid_container.pack(fill=tk.BOTH, expand=True)
        
        row, col = 0, 0
        max_cols = 4
        
        for var_name, var_data in variables:
            self.create_unified_block(grid_container, var_name, var_data, row, col)
            col += 1
            
            if col >= max_cols:
                col = 0
                row += 1
        
        for i in range(max_cols):
            grid_container.grid_columnconfigure(i, weight=1, uniform="col")
        for i in range(row + 1):
            grid_container.grid_rowconfigure(i, weight=0)
    
    def create_tables_grid(self, parent, tables: List):
        grid_container = tk.Frame(parent, bg=self.colors['bg'])
        grid_container.pack(fill=tk.BOTH, expand=True)
        
        row, col = 0, 0
        max_cols = 2
        
        for var_name, var_data in tables:
            self.create_table_block(grid_container, var_name, var_data, row, col)
            col += 1
            
            if col >= max_cols:
                col = 0
                row += 1
        
        for i in range(max_cols):
            grid_container.grid_columnconfigure(i, weight=1, uniform="col")
        for i in range(row + 1):
            grid_container.grid_rowconfigure(i, weight=0)
    
    def create_unified_block(self, parent, var_name: str, var_data: Dict, row: int, col: int):
        block = tk.Frame(parent, bg=self.colors['surface'], bd=1, relief='flat',
                        highlightbackground=self.colors['border'], highlightthickness=1)
        block.grid(row=row, column=col, padx=6, pady=6, sticky='nsew')
        
        content_frame = tk.Frame(block, bg=self.colors['surface'], padx=12, pady=10)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        top_frame = tk.Frame(content_frame, bg=self.colors['surface'])
        top_frame.pack(fill=tk.X, pady=(0, 8))
        
        display_name = var_data.get('ui_name', var_name.replace('_', ' ').title())
        name_label = tk.Label(top_frame,
                            text=display_name,
                            font=('Segoe UI', 10, 'bold'),
                            bg=self.colors['surface'],
                            fg=self.colors['text'],
                            wraplength=140,
                            anchor='w',
                            justify=tk.LEFT)
        name_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        right_top_frame = tk.Frame(top_frame, bg=self.colors['surface'])
        right_top_frame.pack(side=tk.RIGHT, fill=tk.Y)
        
        tags = var_data.get('ui_tags', [])
        tag_colors = var_data.get('ui_tag_colors', {})
        
        if tags:
            tags_frame = tk.Frame(right_top_frame, bg=self.colors['surface'])
            tags_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
            
            for i, tag in enumerate(tags[:3]):
                tag_color = None
                tag_upper = tag.upper()
                
                if tag_upper in tag_colors:
                    tag_color = tag_colors[tag_upper]
                elif 'DEFAULT' in tag_colors:
                    tag_color = tag_colors['DEFAULT']
                elif tag_upper in ['RED', 'GREEN', 'BLUE', 'YELLOW', 'ORANGE', 
                                  'PURPLE', 'CYAN', 'PINK', 'GRAY']:
                    tag_color = tag_upper
                
                tag_badge = self.create_tag_badge(tags_frame, tag, tag_color)
                tag_badge.pack(side=tk.LEFT, padx=(0, 2))
        
        display_type = 'selector' if var_data.get('ui_selector') else var_data['type']
        type_badge = tk.Label(right_top_frame,
                            text=display_type.upper(),
                            font=('Segoe UI', 7, 'bold'),
                            bg=self.colors['type_badge'],
                            fg=self.colors['text_secondary'],
                            padx=6,
                            pady=2,
                            relief='flat',
                            bd=0)
        type_badge.pack(side=tk.RIGHT)
        
        if var_data.get('ui_hint'):
            hint_lines = var_data['ui_hint'].split('\n')
            for hint_line in hint_lines:
                if hint_line.strip():
                    hint_label = tk.Label(content_frame,
                                        text=hint_line.strip(),
                                        font=('Segoe UI', 8),
                                        bg=self.colors['surface'],
                                        fg=self.colors['text_secondary'],
                                        wraplength=180,
                                        justify=tk.LEFT,
                                        anchor='w')
                    hint_label.pack(anchor='w', pady=(0, 2))
        
        control_frame = tk.Frame(content_frame, bg=self.colors['surface'])
        control_frame.pack(fill=tk.X, pady=(6, 0))
        
        if var_data.get('ui_selector'):
            control = self.create_compact_selector(control_frame, var_name, var_data)
            self.controls[var_name] = control
        elif var_data['type'] == 'boolean':
            control = self.create_compact_toggle(control_frame, var_data['value'])
            self.controls[var_name] = control
        else:
            control = self.create_compact_input(control_frame, var_data)
            self.controls[var_name] = control
        
        has_ui_config = var_data.get('ui_name') or var_data.get('ui_hint') or var_data.get('ui_selector') or var_data.get('ui_tags')
        if not has_ui_config:
            tech_label = tk.Label(content_frame,
                                text=var_name,
                                font=('Segoe UI', 6),
                                bg=self.colors['surface'],
                                fg=self.colors['text_muted'])
            tech_label.pack(anchor='w', pady=(8, 0))
    
    def create_table_block(self, parent, var_name: str, var_data: Dict, row: int, col: int):
        block = tk.Frame(parent, bg=self.colors['surface'], bd=1, relief='flat',
                        highlightbackground=self.colors['border'], highlightthickness=1)
        block.grid(row=row, column=col, padx=6, pady=6, sticky='nsew')
        
        content_frame = tk.Frame(block, bg=self.colors['surface'], padx=12, pady=10)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        header_frame = tk.Frame(content_frame, bg=self.colors['surface'])
        header_frame.pack(fill=tk.X, pady=(0, 8))
        
        left_header = tk.Frame(header_frame, bg=self.colors['surface'])
        left_header.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        display_name = var_data.get('ui_name', var_name.replace('_', ' ').title())
        name_label = tk.Label(left_header,
                            text=display_name,
                            font=('Segoe UI', 11, 'bold'),
                            bg=self.colors['surface'],
                            fg=self.colors['text'])
        name_label.pack(anchor='w')
        
        right_header = tk.Frame(header_frame, bg=self.colors['surface'])
        right_header.pack(side=tk.RIGHT, fill=tk.Y)
        
        tags = var_data.get('ui_tags', [])
        tag_colors = var_data.get('ui_tag_colors', {})
        
        if tags:
            tags_frame = tk.Frame(right_header, bg=self.colors['surface'])
            tags_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 5))
            
            for i, tag in enumerate(tags[:2]):
                tag_color = None
                tag_upper = tag.upper()
                
                if tag_upper in tag_colors:
                    tag_color = tag_colors[tag_upper]
                elif 'DEFAULT' in tag_colors:
                    tag_color = tag_colors['DEFAULT']
                elif tag_upper in ['RED', 'GREEN', 'BLUE', 'YELLOW', 'ORANGE', 
                                  'PURPLE', 'CYAN', 'PINK', 'GRAY']:
                    tag_color = tag_upper
                
                tag_badge = self.create_tag_badge(tags_frame, tag, tag_color)
                tag_badge.pack(side=tk.LEFT, padx=(0, 3))
        
        field_count = len(var_data['value']) if isinstance(var_data['value'], dict) else 0
        count_badge = tk.Label(right_header,
                         text=f"{field_count} fields",
                         font=('Segoe UI', 7),
                         bg=self.colors['type_badge'],
                         fg=self.colors['text_secondary'],
                         padx=6,
                         pady=2,
                        relief='flat',
                        bd=0)
        count_badge.pack(side=tk.RIGHT, padx=(5, 0))
        
        is_expanded = var_name in self.expanded_tables
        expand_text = "Hide" if is_expanded else "Show"
        
        expand_btn = ttk.Button(right_header,
                          text=expand_text,
                          command=lambda: self.toggle_table_expansion(var_name, block, var_data, expand_btn),
                          style='Expand.TButton')
        expand_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        if var_data.get('ui_hint'):
            hint_lines = var_data['ui_hint'].split('\n')
            for hint_line in hint_lines:
                if hint_line.strip():
                    hint_label = tk.Label(content_frame,
                                        text=hint_line.strip(),
                                        font=('Segoe UI', 8),
                                        bg=self.colors['surface'],
                                        fg=self.colors['text_secondary'],
                                        wraplength=300,
                                        justify=tk.LEFT,
                                        anchor='w')
                    hint_label.pack(anchor='w', pady=(0, 2))
        
        table_content_frame = tk.Frame(content_frame, bg=self.colors['surface'])
        self.table_content_frames[var_name] = table_content_frame
        
        if is_expanded:
            self.create_table_controls(var_name, var_data, table_content_frame)
            table_content_frame.pack(fill=tk.X, pady=(8, 0))
        
        tech_label = tk.Label(content_frame,
                            text=var_name,
                            font=('Segoe UI', 6),
                            bg=self.colors['surface'],
                            fg=self.colors['text_muted'])
        tech_label.pack(anchor='w', pady=(8, 0))
    
    def toggle_table_expansion(self, var_name: str, block, var_data: Dict, expand_btn):
        table_content_frame = self.table_content_frames.get(var_name)
        
        if not table_content_frame:
            return
        
        if var_name in self.expanded_tables:
            for widget in table_content_frame.winfo_children():
                widget.destroy()
            table_content_frame.pack_forget()
            self.expanded_tables.remove(var_name)
            expand_btn.configure(text="Show")
        else:
            self.create_table_controls(var_name, var_data, table_content_frame)
            table_content_frame.pack(fill=tk.X, pady=(8, 0))
            self.expanded_tables.add(var_name)
            expand_btn.configure(text="Hide")
        
        block.update_idletasks()
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self.update_slider_position()
    
    def create_table_controls(self, var_name: str, var_data: Dict, parent_frame):
        table_controls = {}
        table_value = var_data['value']
        
        if not table_value or not isinstance(table_value, dict):
            empty_label = tk.Label(parent_frame,
                                 text="No fields found in table",
                                 font=('Segoe UI', 8),
                                 bg=self.colors['surface'],
                                 fg=self.colors['text_secondary'])
            empty_label.pack(pady=8)
            return
        
        subtable_container = tk.Frame(parent_frame, bg=self.colors['surface_light'], 
                                     relief='flat', bd=1, highlightbackground=self.colors['border'],
                                     highlightthickness=1)
        subtable_container.pack(fill=tk.X, pady=(8, 0))
        
        inner_container = tk.Frame(subtable_container, bg=self.colors['surface_light'], padx=10, pady=8)
        inner_container.pack(fill=tk.X, expand=True)
        
        subtable_header = tk.Frame(inner_container, bg=self.colors['surface_light'])
        subtable_header.pack(fill=tk.X, pady=(0, 8))
        
        subtable_title = tk.Label(subtable_header,
                                text="TABLE FIELDS",
                                font=('Segoe UI', 9, 'bold'),
                                bg=self.colors['surface_light'],
                                fg=self.colors['text_secondary'])
        subtable_title.pack(side=tk.LEFT)
        
        simple_fields = [k for k, v in table_value.items() if not isinstance(v, dict)]
        fields_count = len(simple_fields)
        
        count_label = tk.Label(subtable_header,
                             text=f"{fields_count} fields",
                             font=('Segoe UI', 7),
                             bg=self.colors['type_badge'],
                             fg=self.colors['text_secondary'],
                             padx=6, pady=2)
        count_label.pack(side=tk.RIGHT)
        
        fields_grid = tk.Frame(inner_container, bg=self.colors['surface_light'])
        fields_grid.pack(fill=tk.X)
        
        row, col = 0, 0
        max_cols = 2
        
        for field_key, field_value in table_value.items():
            if isinstance(field_value, dict):
                continue
                
            field_frame = tk.Frame(fields_grid, bg=self.colors['surface_light'])
            field_frame.grid(row=row, column=col, padx=8, pady=6, sticky='ew')
            
            field_metadata = var_data.get('table_fields', {}).get(str(field_key), {})
            field_display_name = field_metadata.get('name', str(field_key).replace('_', ' ').title())
            
            field_main_frame = tk.Frame(field_frame, bg=self.colors['surface_light'])
            field_main_frame.pack(fill=tk.X, expand=True)
            
            field_top_frame = tk.Frame(field_main_frame, bg=self.colors['surface_light'])
            field_top_frame.pack(fill=tk.X, pady=(0, 4))
            
            field_label = tk.Label(field_top_frame,
                                 text=field_display_name,
                                 font=('Segoe UI', 9, 'bold'),
                                 bg=self.colors['surface_light'],
                                 fg=self.colors['text'],
                                 anchor='w',
                                 justify=tk.LEFT)
            field_label.pack(side=tk.LEFT, fill=tk.X, expand=True)
            
            control_container = tk.Frame(field_top_frame, bg=self.colors['surface_light'])
            control_container.pack(side=tk.RIGHT)
            
            if field_metadata.get('selector'):
                control = self.create_compact_selector(control_container, f"{var_name}.{field_key}", {
                    'value': field_value,
                    'ui_selector': self.parser._parse_selector(field_metadata['selector'], 'string'),
                    'type': 'selector'
                })
                table_controls[field_key] = control
            elif isinstance(field_value, bool):
                control = self.create_compact_toggle(control_container, field_value)
                table_controls[field_key] = control
            elif isinstance(field_value, (int, float)):
                control = self.create_compact_input(control_container, {
                    'value': field_value,
                    'type': 'number'
                })
                table_controls[field_key] = control
            else:
                control = self.create_compact_input(control_container, {
                    'value': str(field_value),
                    'type': 'string'
                })
                table_controls[field_key] = control
            
            field_bottom_frame = tk.Frame(field_main_frame, bg=self.colors['surface_light'])
            field_bottom_frame.pack(fill=tk.X)
            
            if field_metadata.get('hint'):
                hint_lines = field_metadata['hint'].split('\n')
                for hint_line in hint_lines:
                    if hint_line.strip():
                        hint_label = tk.Label(field_bottom_frame,
                                            text=hint_line.strip(),
                                            font=('Segoe UI', 8),
                                            bg=self.colors['surface_light'],
                                            fg=self.colors['text_muted'],
                                            wraplength=200,
                                            justify=tk.LEFT,
                                            anchor='w')
                        hint_label.pack(fill=tk.X, pady=(0, 2))
            
            has_field_ui_config = field_metadata.get('name') or field_metadata.get('hint') or field_metadata.get('selector')
            if not has_field_ui_config:
                tech_label = tk.Label(field_bottom_frame,
                                    text=str(field_key),
                                    font=('Segoe UI', 8),
                                    bg=self.colors['surface_light'],
                                    fg=self.colors['text_muted'])
                tech_label.pack(anchor='w')
            
            col += 1
            if col >= max_cols:
                col = 0
                row += 1
        
        for i in range(max_cols):
            fields_grid.columnconfigure(i, weight=1)
        
        if fields_count == 0:
            empty_label = tk.Label(inner_container,
                                 text="No simple fields found in table",
                                 font=('Segoe UI', 8),
                                 bg=self.colors['surface_light'],
                                 fg=self.colors['text_secondary'])
            empty_label.pack(pady=8)
        
        self.controls[var_name] = {
            'type': 'table',
            'controls': table_controls
        }
    
    def create_compact_toggle(self, parent, initial_value: bool):
        toggle_frame = tk.Frame(parent, bg=self.colors['surface_light'])
        toggle_frame.pack(side=tk.RIGHT)
        
        state = tk.BooleanVar(value=initial_value)
        
        toggle_bg = tk.Frame(toggle_frame, 
                            bg=self.colors['toggle_on'] if initial_value else self.colors['toggle_off'],
                            width=50, height=24, bd=0,
                            cursor="hand2", relief='flat')
        toggle_bg.pack_propagate(False)
        toggle_bg.pack(side=tk.LEFT)
        
        text_label = tk.Label(toggle_bg,
                            text="ON" if initial_value else "OFF",
                            font=('Segoe UI', 7, 'bold'),
                            bg=self.colors['toggle_on'] if initial_value else self.colors['toggle_off'],
                            fg=self.colors['text'])
        text_label.place(relx=0.5, rely=0.5, anchor='center')
        
        def toggle_switch():
            new_value = not state.get()
            state.set(new_value)
            toggle_bg.configure(bg=self.colors['toggle_on'] if new_value else self.colors['toggle_off'])
            text_label.configure(
                text="ON" if new_value else "OFF",
                bg=self.colors['toggle_on'] if new_value else self.colors['toggle_off']
            )
        
        toggle_bg.bind("<Button-1>", lambda e: toggle_switch())
        text_label.bind("<Button-1>", lambda e: toggle_switch())
        
        return state
    
    def create_compact_selector(self, parent, var_name: str, var_data: Dict):
        selector_frame = tk.Frame(parent, bg=self.colors['surface_light'])
        selector_frame.pack(side=tk.RIGHT)
        
        selector_options = var_data.get('ui_selector', {})
        
        if not selector_options:
            return self.create_compact_input(parent, var_data)
        
        option_values = list(selector_options.keys())
        option_display = [str(selector_options.get(k, k)) for k in option_values]
        
        selector_combo = ttk.Combobox(selector_frame,
                                    values=option_display,
                                    state="readonly",
                                    width=16,
                                    style='Modern.TCombobox',
                                    font=('Segoe UI', 9))
        selector_combo.pack(side=tk.RIGHT)
        
        try:
            self.root.tk.eval(f'''
                [ttk::combobox::PopdownWindow {selector_combo}]::listbox configure \
                -background #1a1a1a \
                -foreground #ffffff \
                -selectbackground #007acc \
                -selectforeground #ffffff \
                -font {{Segoe UI 9}} \
                -borderwidth 0 \
                -highlightthickness 0 \
                -relief flat
            ''')
        except:
            pass
        
        current_value = var_data['value']
        
        current_index = -1
        
        if current_value in option_values:
            current_index = option_values.index(current_value)
        else:
            for i, key in enumerate(option_values):
                display_val = selector_options.get(key, key)
                if str(current_value) == str(display_val):
                    current_index = i
                    break
            
            if current_index == -1:
                for i, display_val in enumerate(option_display):
                    if str(current_value) == str(display_val):
                        current_index = i
                        break
        
        if current_index >= 0:
            selector_combo.current(current_index)
        elif option_display:
            selector_combo.current(0)

        return {
            'control': selector_combo,
            'values': option_values,
            'display_values': option_display,
            'options': selector_options
        }
    
    def create_compact_input(self, parent, var_data: Dict):
        input_frame = tk.Frame(parent, bg=self.colors['surface_light'])
        input_frame.pack(side=tk.RIGHT)
        
        value_type = var_data.get('type', 'string')
        current_value = var_data['value']
        
        if value_type in ['integer', 'float', 'number']:
            validate_cmd = (input_frame.register(self.validate_number), '%P')
            entry = ttk.Entry(input_frame,
                             width=12,
                             style='Compact.TEntry',
                             font=('Segoe UI', 9),
                             validate='key',
                             validatecommand=validate_cmd)
            entry.insert(0, str(current_value))
        else:
            entry = ttk.Entry(input_frame,
                             width=12,
                             style='Compact.TEntry',
                             font=('Segoe UI', 9))
            entry.insert(0, str(current_value))
        
        entry.pack(side=tk.RIGHT)
        
        return entry

    def validate_number(self, value):
        if value == "" or value == "-":
            return True
        try:
            float(value)
            return True
        except ValueError:
            return False
    
    def show_empty_state(self):
        empty_frame = tk.Frame(self.scrollable_frame, bg=self.colors['bg'])
        empty_frame.pack(expand=True, fill=tk.BOTH, pady=100)
        
        empty_icon = tk.Label(empty_frame,
                            text="📄",
                            font=('Segoe UI', 48),
                            bg=self.colors['bg'],
                            fg=self.colors['text_secondary'])
        empty_icon.pack(pady=(0, 20))
        
        empty_label = tk.Label(empty_frame,
                             text="No configuration variables found",
                             font=('Segoe UI', 14, 'bold'),
                             bg=self.colors['bg'],
                             fg=self.colors['text_secondary'])
        empty_label.pack(pady=(0, 10))
        
        sub_label = tk.Label(empty_frame,
                           text="This file doesn't contain readable configuration variables",
                           font=('Segoe UI', 10),
                           bg=self.colors['bg'],
                           fg=self.colors['text_muted'])
        sub_label.pack(pady=(0, 30))
        
        back_btn = ttk.Button(empty_frame,
                            text="← Back to Files Selection",
                            command=self.return_to_files_selection,
                            style='Secondary.TButton')
        back_btn.pack()
    
    def save_changes(self):
        if not self.lua_file_path:
            file_path = filedialog.asksaveasfilename(
                title="Save Lua File",
                filetypes=[("Lua files", "*.lua"), ("All files", "*.*")],
                defaultextension=".lua"
            )
            if file_path:
                self.lua_file_path = file_path
                if not os.path.exists(file_path):
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write("--// READ VARIABLES\n\n--// END READ VARIABLES\n")
                self.load_file_from_selection({
                    'path': file_path,
                    'name': Path(file_path).name
                })
            else:
                return
        
        try:
            self._validate_controls()
            
            with open(self.lua_file_path, 'r', encoding='utf-8') as file:
                original_content = file.read()
            
            backup_path = self.lua_file_path + '.backup'
            shutil.copy2(self.lua_file_path, backup_path)
            
            new_content = self.apply_changes(original_content)
            
            with open(self.lua_file_path, 'w', encoding='utf-8') as file:
                file.write(new_content)
            
            self.save_btn.configure(text="Saved!")
            
            if elden_reloader.connected:
                self.save_btn.configure(text="🔄 Recarregando...")
                def do_reload():
                    if not elden_reloader.reload_character():
                        elden_reloader.connect()
                        elden_reloader.reload_character()
                    self.root.after(0, lambda: self.save_btn.configure(text="Saved!"))
                threading.Thread(target=do_reload, daemon=True).start()
            else:
                self.root.after(2000, lambda: self.save_btn.configure(text="Save Changes"))
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save changes:\n{str(e)}")
    
    def _validate_controls(self):
        valid_controls = {}
        
        for var_name, control in self.controls.items():
            if var_name not in self.variables:
                continue
                
            if isinstance(control, dict) and control.get('type') == 'table':
                table_controls = {}
                for field_key, field_control in control['controls'].items():
                    try:
                        if isinstance(field_control, tk.BooleanVar):
                            table_controls[field_key] = field_control
                        elif isinstance(field_control, dict) and 'control' in field_control:
                            if field_control['control'].winfo_exists():
                                table_controls[field_key] = field_control
                        else:
                            if field_control.winfo_exists():
                                table_controls[field_key] = field_control
                    except tk.TclError:
                        continue
                
                if table_controls:
                    valid_controls[var_name] = {
                        'type': 'table',
                        'controls': table_controls
                    }
                    
            elif isinstance(control, dict) and 'control' in control:
                try:
                    if control['control'].winfo_exists():
                        valid_controls[var_name] = control
                except tk.TclError:
                    continue
                    
            elif isinstance(control, tk.BooleanVar):
                valid_controls[var_name] = control
                
            else:
                try:
                    if control.winfo_exists():
                        valid_controls[var_name] = control
                except tk.TclError:
                    continue
        
        self.controls = valid_controls

    def apply_changes(self, content: str) -> str:
        pattern = r'(--// READ VARIABLES\s*)(.*?)(\s*--// END READ VARIABLES)'
        match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
        
        if match:
            before_section = content[:match.start(1)]
            read_variables_comment = match.group(1)
            variables_section = match.group(2)
            end_comment = match.group(3)
            after_section = content[match.end(3):]
            
            modified_section = self._apply_changes_to_content_with_comments(variables_section)
            
            new_content = (
                before_section + 
                read_variables_comment + 
                modified_section + 
                end_comment + 
                after_section
            )
            
            return new_content
        else:
            return self._apply_changes_to_content_with_comments(content)

    def _apply_changes_to_content_with_comments(self, content: str) -> str:
        lines = content.split('\n')
        output_lines = []
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            variable_found = False
            for var_name, control in self.controls.items():
                if var_name not in self.variables:
                    continue
                    
                var_data = self.variables[var_name]
                
                if f'{var_name} =' in line:
                    if var_data['type'] == 'table' and '{' in line:
                        if isinstance(control, dict) and control.get('type') == 'table':
                            table_lines = self._rebuild_table_with_comments(var_name, var_data, control)
                            output_lines.extend(table_lines)
                            
                            brace_count = line.count('{') - line.count('}')
                            i += 1
                            while i < len(lines) and brace_count > 0:
                                brace_count += lines[i].count('{') - lines[i].count('}')
                                i += 1
                            variable_found = True
                            break
                    else:
                        new_value = self._get_control_value(var_name, control, var_data)
                        if new_value is not None:
                            if '--' in line:
                                comment_part = line.split('--', 1)[1]
                                output_lines.append(f'local {var_name} = {new_value} --{comment_part}')
                            else:
                                output_lines.append(f'local {var_name} = {new_value}')
                            i += 1
                            variable_found = True
                            break
            
            if not variable_found:
                output_lines.append(line)
                i += 1
        
        return '\n'.join(output_lines)

    def _get_control_value(self, var_name: str, control, var_data: Dict) -> str:
        try:
            if isinstance(control, tk.BooleanVar):
                return str(control.get()).lower()
            elif isinstance(control, dict) and 'control' in control:
                selected_index = control['control'].current()
                if selected_index >= 0:
                    return str(control['values'][selected_index])
                else:
                    return str(var_data['value'])
            elif hasattr(control, 'get'):
                value = control.get()
                if var_data['type'] in ['integer', 'float']:
                    return value
                elif var_data['type'] == 'string':
                    return f'"{value}"'
                else:
                    return str(value)
            else:
                return str(var_data['value'])
        except Exception:
            return str(var_data['value'])

    def _rebuild_table_with_comments(self, var_name: str, var_data: Dict, control: Dict) -> List[str]:
        table_lines = [f'local {var_name} = {{']
        
        table_controls = control.get('controls', {})
        original_value = var_data.get('value', {})
        
        field_order = list(original_value.keys()) if isinstance(original_value, dict) else []
        
        for field_key in field_order:
            if field_key not in table_controls:
                continue
                
            field_control = table_controls[field_key]
            field_metadata = var_data.get('table_fields', {}).get(str(field_key), {})
            
            if field_metadata.get('name') or field_metadata.get('hint'):
                if field_metadata.get('name'):
                    table_lines.append(f'-- [UI] TABLEFIELD_NAME: {field_metadata["name"]}')
                if field_metadata.get('hint'):
                    table_lines.append(f'-- [UI] TABLEFIELD_HINT: {field_metadata["hint"]}')
            
            new_value = self._get_table_field_value(field_control, original_value.get(field_key))
            
            table_lines.append(f'    {field_key} = {new_value},')
        
        table_lines.append('}')
        
        return table_lines

    def _get_table_field_value(self, field_control, original_value) -> str:
        try:
            if isinstance(field_control, tk.BooleanVar):
                return str(field_control.get()).lower()
            elif isinstance(field_control, dict) and 'control' in field_control:
                selected_index = field_control['control'].current()
                if selected_index >= 0:
                    value = field_control['values'][selected_index]
                else:
                    value = original_value
            elif hasattr(field_control, 'get'):
                value = field_control.get()
            else:
                value = original_value
            
            if isinstance(value, str) and not value.replace('.', '').replace('-', '').isdigit():
                if value.lower() not in ['true', 'false']:
                    value = f'"{value}"'
            
            return str(value)
        except Exception:
            return str(original_value)

def main():
    try:
        root = tk.Tk()
        app = UltraCompactConfigurator(root)
        root.mainloop()
    except Exception as e:
        traceback.print_exc()
        input("Pressione Enter para sair...")

if __name__ == "__main__":
    main()
