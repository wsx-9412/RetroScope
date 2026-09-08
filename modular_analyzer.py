#!/usr/bin/env python3
"""
Enhanced vulnerability migration analysis tool - with integrated rr reverse debugging
Used to precisely locate the input offset positions that affect fork-point variables
"""

import os
import sys
import subprocess
import shutil
import tempfile
import time
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import importlib.util
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import struct
import wave
from PIL import Image
import numpy as np

class FileFormatParser:
    """File format parser that supports multiple input file formats"""
    
    @staticmethod
    def detect_file_type(file_path: Path) -> str:
        """detect the file type"""
        # detect by file extension
        extension = file_path.suffix.lower()
        if extension in ['.wav', '.wave']:
            return 'audiofile'
        elif extension in ['.tiff', '.tif']:
            return 'libtiff'
        elif extension in ['.png']:
            return 'libpng'
        elif extension in ['.mp3']:
            return 'lame'
        elif extension in ['.jp2', '.j2k']:
            return 'jasper'
        else:
            # detect by file header
            with open(file_path, 'rb') as f:
                header = f.read(12)
                if header.startswith(b'RIFF') and b'WAVE' in header:
                    return 'audiofile'
                elif header.startswith(b'II*\x00') or header.startswith(b'MM\x00*'):
                    return 'libtiff'
                elif header.startswith(b'\x89PNG\r\n\x1a\n'):
                    return 'libpng'
                elif header.startswith(b'ID3') or header.startswith(b'\xff\xfb'):
                    return 'lame'
                elif header.startswith(b'\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a'):
                    return 'jasper'
            return 'unknown'
    
    @staticmethod
    def parse_wav_file(file_path: Path) -> Dict:
        """parse the WAV file format"""
        try:
            with wave.open(str(file_path), 'rb') as wav_file:
                format_info = {
                    'nchannels': wav_file.getnchannels(),
                    'sampwidth': wav_file.getsampwidth(),
                    'framerate': wav_file.getframerate(),
                    'nframes': wav_file.getnframes(),
                    'comptype': wav_file.getcomptype(),
                    'compname': wav_file.getcompname(),
                    'header_size': 44  # standard WAV header size
                }
                
                # calculate the offset positions of key fields
                offsets = {
                    'chunk_id': 0,           # 'RIFF'
                    'chunk_size': 4,         # total file size - 8
                    'format': 8,             # 'WAVE'
                    'subchunk1_id': 12,      # 'fmt '
                    'subchunk1_size': 16,    # size of the fmt chunk
                    'audio_format': 20,      # audio format
                    'num_channels': 22,      # number of channels
                    'sample_rate': 24,       # sample rate
                    'byte_rate': 28,         # byte rate
                    'block_align': 32,       # block align
                    'bits_per_sample': 34,   # bit depth
                    'subchunk2_id': 36,      # 'data'
                    'subchunk2_size': 40,    # data size
                    'audio_data': 44         # start of the audio data
                }
                
                format_info['offsets'] = offsets
                return format_info
        except Exception as e:
            print(f"failed to parse WAV file: {e}")
            return {}
    
    @staticmethod
    def parse_tiff_file(file_path: Path) -> Dict:
        """parse the TIFF file format"""
        try:
            img = Image.open(file_path)
            format_info = {
                'width': img.width,
                'height': img.height,
                'mode': img.mode,
                'format': img.format,
                'compression': img.info.get('compression', 'none')
            }
            
            # TIFF file structure offsets
            offsets = {
                'byte_order': 0,     # byte order (II or MM)
                'version': 2,        # version number (42)
                'first_ifd': 4,      # first IFD offset
                'image_width': 8,    # image width (assumed to be in the first IFD)
                'image_height': 10,  # image height
                'bits_per_sample': 12,  # bit depth
                'compression': 14,   # compression method
                'photometric_interpretation': 16,  # photometric interpretation
                'strip_offsets': 18, # strip offsets
                'samples_per_pixel': 20,  # samples per pixel
                'rows_per_strip': 22,     # rows per strip
                'strip_byte_counts': 24   # strip byte counts
            }
            
            format_info['offsets'] = offsets
            return format_info
        except Exception as e:
            print(f"failed to parse TIFF file: {e}")
            return {}
    
    @staticmethod
    def parse_png_file(file_path: Path) -> Dict:
        """parse the PNG file format"""
        try:
            img = Image.open(file_path)
            format_info = {
                'width': img.width,
                'height': img.height,
                'mode': img.mode,
                'format': img.format,
                'info': img.info
            }
            
            # PNG file structure offsets
            offsets = {
                'signature': 0,              # PNG signature (8 bytes)
                'ihdr_chunk_length': 8,      # IHDR length
                'ihdr_chunk_type': 12,       # 'IHDR' (4 bytes)
                'width': 16,                 # image width
                'height': 20,                # image height
                'bit_depth': 24,             # bit depth
                'color_type': 25,            # color type
                'compression_method': 26,    # compression method
                'filter_method': 27,         # filter method
                'interlace_method': 28,      # interlace method
                'ihdr_crc': 29               # IHDR CRC
            }
            
            format_info['offsets'] = offsets
            return format_info
        except Exception as e:
            print(f"failed to parse PNG file: {e}")
            return {}
    
    @staticmethod
    def parse_lame_mp3_file(file_path: Path) -> Dict:
        """parse the MP3 file format"""
        try:
            format_info = {}
            
            # MP3 ID3 tag parsing
            with open(file_path, 'rb') as f:
                header = f.read(10)
                
                if header.startswith(b'ID3'):
                    # ID3v2 tag
                    format_info['id3_version'] = (header[3], header[4])
                    format_info['id3_flags'] = header[5]
                    # ID3 size calculation (syncsafe)
                    id3_size = (header[6] << 21) | (header[7] << 14) | (header[8] << 7) | header[9]
                    format_info['id3_size'] = id3_size
                else:
                    # try to parse the MP3 frame header
                    f.seek(0)
                    frame_header = f.read(4)
                    if len(frame_header) == 4:
                        # check whether it is an MP3 frame header
                        sync = (frame_header[0] << 4) | ((frame_header[1] & 0xF0) >> 4)
                        if sync == 0xFFE:  # MP3 sync word
                            format_info['sync'] = sync
                            format_info['version'] = (frame_header[1] >> 3) & 0x3
                            format_info['layer'] = (frame_header[1] >> 1) & 0x3
                            format_info['protection'] = frame_header[1] & 0x1
                            format_info['bitrate'] = (frame_header[2] >> 4) & 0xF
                            format_info['sample_rate'] = (frame_header[2] >> 2) & 0x3
                            format_info['padding'] = (frame_header[2] >> 1) & 0x1
                            format_info['private'] = frame_header[2] & 0x1
                            format_info['channel_mode'] = (frame_header[3] >> 6) & 0x3
                            format_info['mode_extension'] = (frame_header[3] >> 4) & 0x3
                            format_info['copyright'] = (frame_header[3] >> 3) & 0x1
                            format_info['original'] = (frame_header[3] >> 2) & 0x1
                            format_info['emphasis'] = frame_header[3] & 0x3
            
            offsets = {
                'id3_sync': 0,           # ID3 sync word 'ID3'
                'id3_version_major': 3,  # ID3 major version
                'id3_version_minor': 4,  # ID3 minor version
                'id3_flags': 5,          # ID3 flags
                'id3_size': 6,           # ID3 size (4 bytes)
                'mp3_sync': 0            # MP3 sync word
            }
            
            format_info['offsets'] = offsets
            return format_info
        except Exception as e:
            print(f"failed to parse MP3 file: {e}")
            return {}
    
    @staticmethod
    def parse_jasper_file(file_path: Path) -> Dict:
        """parse the JPEG-2000 file format (Jasper)"""
        try:
            img = Image.open(file_path)
            format_info = {
                'width': img.width,
                'height': img.height,
                'mode': img.mode,
                'format': img.format
            }
            
            # JPEG-2000 file structure offsets
            offsets = {
                'jp2_signature': 0,      # JPEG 2000 signature box
                'jp2_length': 0,         # Box length
                'jp2_type': 4,           # Box type
                'image_width': 8,        # image width
                'image_height': 12,      # image height
                'component_count': 16,   # component count
                'bits_per_component': 17, # bits per component
                'signed_flag': 18,       # signed flag
                'downsampling': 19       # downsampling
            }
            
            format_info['offsets'] = offsets
            return format_info
        except Exception as e:
            print(f"failed to parse JP2 file: {e}")
            return {}

class InputModifierAnalyzer:
    """
    input file modification analyzer
    used to analyze how to modify the input file to make the target version crash
    """
    def __init__(self, target_build_dir: str, input_file: str, related_vars: List[str], 
                 crash_analysis: Dict, execution_config: Dict, ref_crash_type: str):
        self.target_build_dir = Path(target_build_dir)
        self.input_file = Path(input_file)
        self.related_vars = related_vars
        self.crash_analysis = crash_analysis
        self.execution_config = execution_config
        self.ref_crash_type = ref_crash_type  # pass the actual crash type of the reference version
        
        # read the original input file
        with open(self.input_file, 'rb') as f:
            self.original_data = bytearray(f.read())
        
        # detect the file type
        self.file_type = FileFormatParser.detect_file_type(self.input_file)
        print(f"detected file type: {self.file_type}")
        
        # parse the file format
        self.file_format_info = self.parse_file_format()
        
        print(f"Initializing input modification analyzer:")
        print(f"  target build directory: {self.target_build_dir}")
        print(f"  Input file: {self.input_file}")
        print(f"  original file size: {len(self.original_data)} bytes")
        print(f"  related variables: {self.related_vars}")
        print(f"  reference version crash type: {self.ref_crash_type}")
        print(f"  first 16 bytes of the original file content (hex): {' '.join([f'{b:02X}' for b in self.original_data[:16]])}")
        print(f"  first 16 bytes of the actual file content (hex): {' '.join([f'{b:02X}' for b in self.original_data[:16]])}")

    def parse_file_format(self) -> Dict:
        """parse file format information"""
        if self.file_type == 'audiofile':
            return FileFormatParser.parse_wav_file(self.input_file)
        elif self.file_type == 'libtiff':
            return FileFormatParser.parse_tiff_file(self.input_file)
        elif self.file_type == 'libpng':
            return FileFormatParser.parse_png_file(self.input_file)
        elif self.file_type == 'lame':
            return FileFormatParser.parse_lame_mp3_file(self.input_file)
        elif self.file_type == 'jasper':
            return FileFormatParser.parse_jasper_file(self.input_file)
        else:
            return {}

    def find_executable(self, build_dir: Path, version_name: str = "") -> Optional[Path]:
        """find the compiled executable"""
        # first try to find it according to the config
        exec_config = self.execution_config
        if exec_config and "program_name" in exec_config:
            program_name = exec_config["program_name"]
            
            # if a build directory pattern is configured, search under that pattern first
            if "build_dir_pattern" in exec_config:
                build_pattern = exec_config["build_dir_pattern"]
                search_path = build_dir / build_pattern.lstrip('/')
                if search_path.exists():
                    for root, dirs, files in os.walk(search_path):
                        for file in files:
                            file_path = Path(root) / file
                            if file == program_name and os.access(file_path, os.X_OK):
                                return file_path

            # not found in the pattern directory: search the entire build directory by name (prefer ELF binaries)
            best_match = None
            for root, dirs, files in os.walk(build_dir):
                # exclude CMake test artifacts, build helpers and test directories
                dirs[:] = [d for d in dirs if d not in
                           ('.git', 'test', 'tests', 'contrib', 'CMakeFiles',
                            'CheckTypeSize', '.deps')]
                if 'CMakeFiles' in root or 'CheckTypeSize' in root or '/test' in root:
                    continue
                for file in files:
                    if file == program_name:
                        file_path = Path(root) / file
                        if os.access(file_path, os.X_OK):
                            try:
                                if open(file_path, 'rb').read(4) == b'\x7fELF':
                                    return file_path
                            except Exception:
                                pass
                            if best_match is None:
                                best_match = file_path
            return best_match
        
        # if no program name is specified in the config, use the default search method
        # first try to find executables with specific names
        possible_names = ["sfconvert", "audiofile", "afile", "convert", "main", "program", "imginfo", "tiffcrop", "tiffcp"]
        
        for name in possible_names:
            exe_path = build_dir / name
            if exe_path.is_file() and os.access(exe_path, os.X_OK):
                return exe_path
        
        # if the specific names are not found, search all executables (accept only ELF binaries, exclude configure and other scripts)
        for root, dirs, files in os.walk(build_dir):
            dirs[:] = [d for d in dirs if d not in ('.git', 'test', 'tests', 'contrib')]
            for file in files:
                if file in {"configure", "config.status", "libtool", "install-sh",
                            "missing", "depcomp", "compile", "ltmain.sh"}:
                    continue
                file_path = Path(root) / file
                try:
                    if (file_path.is_file() and os.access(file_path, os.X_OK)
                            and open(file_path, 'rb').read(4) == b'\x7fELF'):
                        return file_path
                except Exception:
                    continue
        return None

    def run_program_with_sanitizer(self, program_path: Path, input_data: bytes, timeout: int = 10) -> Dict:
        """
        Run the target program and obtain the execution result
        """
        # create a temporary input file
        temp_input = Path(tempfile.mktemp(suffix=".tmp"))
        temp_input.write_bytes(input_data)
        
        # create a temporary output file
        temp_output = Path(tempfile.mktemp(suffix="_out.tmp"))
        
        # set environment variables
        env = os.environ.copy()
        env.update({
            "ASAN_OPTIONS": "abort_on_error=1:symbolize=1:print_stats=0:halt_on_error=1",
            "UBSAN_OPTIONS": "abort_on_error=1:symbolize=1"
        })
        
        # build the command (adjust the command format as needed)
        if self.execution_config and "command_format" in self.execution_config:
            cmd_template = self.execution_config["command_format"]
            cmd = cmd_template.format(
                program_path=program_path,
                input_file=temp_input,
                output_file=temp_output
            ).split()
        else:
            cmd = [str(program_path), str(temp_input), str(temp_output)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            
            # analyze the output to determine the crash type
            stderr = result.stderr
            stdout = result.stdout
            
            # check the crash type
            crash_type = "no_crash"
            crash_reason = ""
            
            if result.returncode != 0:
                if "division by zero" in stderr.lower() or "floating-point-exception" in stderr.lower():
                    crash_type = "division_by_zero"
                    crash_reason = "division by zero"
                elif "heap-buffer-overflow" in stderr.lower():
                    crash_type = "heap_buffer_overflow"
                    crash_reason = "heap buffer overflow"
                elif "FPE" in stderr or "floating-point-exception" in stderr.lower():
                    crash_type = "FPE"
                    crash_reason = "float point exception"
                elif "detected memory leaks" in stderr.lower():
                    crash_type = "detected memory leaks"
                    crash_reason = "detected memory leaks"
                elif "stack-buffer-overflow" in stderr.lower():
                    crash_type = "stack_buffer_overflow"
                    crash_reason = "stack buffer overflow"
                elif "SEGV" in stderr or "segmentation fault" in stderr.lower():
                    crash_type = "segfault"
                    crash_reason = "segmentation fault"
                elif "use-after-free" in stderr.lower():
                    crash_type = "use_after_free"
                    crash_reason = "use after free"
                elif "Killed" in stderr or "killed" in stderr.lower():
                    crash_type = "killed"
                    crash_reason = "process was killed"
                elif "Bus error" in stderr or "bus error" in stderr.lower():
                    crash_type = "bus_error"
                    crash_reason = "bus error"
                elif "Illegal instruction" in stderr or "illegal instruction" in stderr.lower():
                    crash_type = "illegal_instruction"
                    crash_reason = "illegal instruction"
                else:
                    # check whether it is just an error message rather than a crash
                    error_keywords = ["Error", "Failed", "Invalid", "Incorrect", "expecting", 
                                     "missing", "no space", "integer overflow", "allocate memory"]
                    crash_keywords = ["Segmentation fault", "SEGV", "Aborted", "SIGSEGV", 
                                     "SIGABRT", "AddressSanitizer", "asan", "heap-buffer", 
                                     "stack-buffer", "use-after-free", "double-free"]
                    
                    has_error = any(keyword.lower() in stderr.lower() for keyword in error_keywords)
                    has_crash = any(keyword.lower() in stderr.lower() for keyword in crash_keywords)
                    
                    if has_crash:
                        crash_type = "other_crash"
                        crash_reason = "other crash"
                    elif has_error:
                        crash_type = "error_handling"
                        crash_reason = "normal program error handling"
                    else:
                        crash_type = "other_non_crash"
                        crash_reason = "other non-crash error"
            else:
                crash_type = "no_crash"
                crash_reason = "program executed normally"
            
            # extract the stack trace
            stack_trace = self.extract_detailed_stack_trace(stderr)
            
            return {
                "returncode": result.returncode,
                "crashed": result.returncode != 0 and crash_type not in ["error_handling", "no_crash", "other_non_crash"],
                "crash_type": crash_type,
                "crash_reason": crash_reason,
                "stderr": stderr,
                "stdout": stdout,
                "execution_success": result.returncode == 0,
                "stack_trace": stack_trace
            }
            
        except subprocess.TimeoutExpired:
            return {
                "returncode": -999,
                "crashed": True,
                "crash_type": "timeout",
                "crash_reason": "program timed out",
                "stderr": "TIMEOUT",
                "stdout": "",
                "execution_success": False,
                "stack_trace": []
            }
        except Exception as e:
            return {
                "returncode": -998,
                "crashed": True,
                "crash_type": "execution_error",
                "crash_reason": f"execution error: {str(e)}",
                "stderr": str(e),
                "stdout": "",
                "execution_success": False,
                "stack_trace": []
            }
        finally:
            # clean up temporary files
            try:
                temp_input.unlink()
                temp_output.unlink()
            except:
                pass

    def extract_detailed_stack_trace(self, stderr: str) -> List[Dict[str, str]]:
        """extract detailed stack trace information, including file and line numbers"""
        lines = stderr.split('\n')
        stack_trace = []
        
        # find the start marker of the ASAN stack trace
        for line in lines:
            line = line.strip()
            
            # check whether it is an ASAN stack line (format: #number 0xaddress in function_name file:line)
            asan_match = re.match(r'#(\d+) 0x[0-9a-fA-F]+ in (.*?)(?:\s+\((.*)\))?$', line)
            if asan_match:
                frame_num = asan_match.group(1)
                func_info = asan_match.group(2).strip()
                
                # extract the function name
                func_name_match = re.search(r'([^(]+)', func_info)
                if func_name_match:
                    func_name = func_name_match.group(1).strip()
                else:
                    func_name = func_info
                
                # extract the file and line number information
                file_line = ""
                if asan_match.group(3):  # there is information inside parentheses
                    file_line = asan_match.group(3).strip()
                else:
                    # try to extract file:line from the function information
                    file_line_match = re.search(r'(/[^:]+:\d+)', func_info)
                    if file_line_match:
                        file_line = file_line_match.group(1)
                
                stack_frame = {
                    "frame": int(frame_num),
                    "function": func_name,
                    "file_line": file_line,
                    "raw_line": line
                }
                stack_trace.append(stack_frame)
        
        return stack_trace

    def normalize_crash_type(self, crash_type: str) -> str:
        """
        normalize crash types so that similar types match
        """
        if crash_type is None:
            return "unknown"
        
        # remove hyphens and convert to lowercase for better matching
        normalized = crash_type.lower().replace("-", "_").replace(" ", "_")
        
        # define the similar type mapping
        type_mappings = {
            "heap_buffer_overflow": "heap_buffer_overflow",
            "heap_buffer_overflow": "heap_buffer_overflow",
            "stack_buffer_overflow": "stack_buffer_overflow",
            "stack_buffer_overflow": "stack_buffer_overflow",
            "segfault": "segv",
            "segv": "segfault",
            "other_crash": "other_crash",
            "heap-buffer-overflow": "heap_buffer_overflow",
            "stack-buffer-overflow": "stack_buffer_overflow",
            "heap_buffer_overflow": "heap_buffer_overflow",
            "heap_buffer_overflow": "heap_buffer_overflow",
            "use_after_free": "use_after_free",
            "use_after_free": "use_after_free",
            "double_free": "double_free",
            "double_free": "double_free",
            "global_buffer_overflow": "global_buffer_overflow",
            "global_buffer_overflow": "global_buffer_overflow",
            "stack_overflow": "stack_overflow",
            "stack_overflow": "stack_overflow",
            "floating_point_exception": "floating_point_exception",
            "divide_by_zero": "divide_by_zero",
            "error_handling": "error_handling",
            "other_non_crash": "other_non_crash",
            "timeout": "timeout",
            "execution_error": "execution_error",
            "killed": "killed",
            "bus_error": "bus_error",
            "illegal_instruction": "illegal_instruction"
        }
        
        return type_mappings.get(normalized, normalized)

    def format_aware_modifier(self) -> Dict:
        """
        structure-aware fuzzing - make targeted modifications based on the file format
        """
        print(f"Start structure-aware fuzzing...")
        
        # find the target version executable
        target_program = self.find_executable(self.target_build_dir, "target")
        if not target_program:
            # try to find it in subdirectories
            for subdir in ['sfcommands', 'src', 'bin', 'tools']:
                subdir_path = self.target_build_dir / subdir
                if subdir_path.exists():
                    target_program = self.find_executable(subdir_path, "target")
                    if target_program:
                        break
        
        if not target_program:
            print(f"Error: target version executable not found")
            return {
                "error": "target version executable not found",
                "test_results": []
            }
        
        print(f"Using target program: {target_program}")
        
        triggering_modifications = []  # only record modifications that trigger the same vulnerability
        crash_inducing_modifications = []  # record all crash-inducing modifications
        
        # record the start time
        start_time = time.time()
        
        # set for deduplication that records discovered crash type combinations
        seen_crash_combinations = set()
        
        # if the file format is known, test boundary values for the key fields
        if self.file_format_info and 'offsets' in self.file_format_info:
            offsets = self.file_format_info['offsets']
            
            for field_name, offset in offsets.items():
                if offset < len(self.original_data):
                    original_value = self.original_data[offset]
                    
                    # apply different boundary value tests according to the field type
                    if field_name in ['width', 'height', 'sample_rate', 'nframes', 'framerate', 'nchannels', 'sampwidth']:
                        # size/rate fields, test boundary values
                        boundary_values = [0, 1, 255, 65535, 0xFFFFFFFF, 0x80000000]
                    elif field_name in ['bits_per_sample', 'compression', 'audio_format']:
                        # type/format fields, test boundary values
                        boundary_values = [0, 1, 255, 0xFF]
                    elif field_name in ['chunk_size', 'subchunk2_size', 'byte_rate']:
                        # size fields, test large values
                        boundary_values = [0, 1, 0x7FFFFFFF, 0xFFFFFFFF, 0x80000000]
                    else:
                        # default boundary values
                        boundary_values = [0, 1, 255, 0xFF]
                    
                    for new_value in boundary_values:
                        # multi-byte fields need special handling
                        if field_name in ['width', 'height', 'sample_rate', 'nframes', 'framerate', 'byte_rate', 'chunk_size', 'subchunk2_size']:
                            # assume these are 32-bit integers (4 bytes)
                            if offset + 3 < len(self.original_data):
                                # get the original value
                                original_int = int.from_bytes(self.original_data[offset:offset+4], byteorder='little')
                                # create the modified value
                                if new_value == 0xFFFFFFFF:
                                    new_int = 0xFFFFFFFF
                                elif new_value == 0x80000000:
                                    new_int = 0x80000000
                                elif new_value == 0x7FFFFFFF:
                                    new_int = 0x7FFFFFFF
                                else:
                                    new_int = new_value & 0xFFFFFFFF  # limit to a 32-bit unsigned integer
                                
                                modified_data = self.original_data.copy()
                                modified_data[offset:offset+4] = new_int.to_bytes(4, byteorder='little')
                                
                                result = self.run_program_with_sanitizer(target_program, modified_data)
                                
                                if result["crashed"]:
                                    # create an identifier for deduplication
                                    crash_signature = (
                                        offset,
                                        new_int,
                                        result["crash_type"],
                                        tuple(sorted([frame["function"] for frame in result["stack_trace"][:3]]))  # only consider the first 3 stack frames
                                    )
                                    
                                    if crash_signature not in seen_crash_combinations:
                                        seen_crash_combinations.add(crash_signature)
                                        
                                        # calculate the discovery time
                                        current_time = time.time()
                                        elapsed_time = current_time - start_time
                                        
                                        crash_info = {
                                            "offset": offset,
                                            "field_name": field_name,
                                            "original_value": original_int,
                                            "new_value": new_int,
                                            "crash_type": result["crash_type"],
                                            "crash_reason": result["crash_reason"],
                                            "stack_trace": result["stack_trace"],
                                            "stderr": result["stderr"][:500],  # keep only the first 500 characters
                                            "found_time": f"{elapsed_time:.2f}s",
                                            "description": f"format-aware modification: {field_name}(offset 0x{offset:02X}): {original_int} -> {new_int} caused {result['crash_type']} crash"
                                        }
                                        crash_inducing_modifications.append(crash_info)
                                        
                                        # check whether it matches the reference version crash type
                                        normalized_actual_crash_type = self.normalize_crash_type(result["crash_type"])
                                        normalized_ref_crash_type = self.normalize_crash_type(self.ref_crash_type)
                                        
                                        if normalized_actual_crash_type == normalized_ref_crash_type:
                                            triggering_modifications.append(crash_info)
                                            print(f"  ✓ {crash_info['description']} (matches the reference version crash type: {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                                        else:
                                            print(f"  ~ {crash_info['description']} (does not match the reference version crash type: {normalized_actual_crash_type} vs {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                        else:
                            # single-byte field handling
                            new_byte = new_value & 0xFF
                            if new_byte != original_value:
                                modified_data = self.original_data.copy()
                                modified_data[offset] = new_byte
                                
                                result = self.run_program_with_sanitizer(target_program, modified_data)
                                
                                if result["crashed"]:
                                    # create an identifier for deduplication
                                    crash_signature = (
                                        offset,
                                        new_byte,
                                        result["crash_type"],
                                        tuple(sorted([frame["function"] for frame in result["stack_trace"][:3]]))  # only consider the first 3 stack frames
                                    )
                                    
                                    if crash_signature not in seen_crash_combinations:
                                        seen_crash_combinations.add(crash_signature)
                                        
                                        # calculate the discovery time
                                        current_time = time.time()
                                        elapsed_time = current_time - start_time
                                        
                                        crash_info = {
                                            "offset": offset,
                                            "field_name": field_name,
                                            "original_value": original_value,
                                            "new_value": new_byte,
                                            "crash_type": result["crash_type"],
                                            "crash_reason": result["crash_reason"],
                                            "stack_trace": result["stack_trace"],
                                            "stderr": result["stderr"][:500],  # keep only the first 500 characters
                                            "found_time": f"{elapsed_time:.2f}s",
                                            "description": f"format-aware modification: {field_name}(offset 0x{offset:02X}): 0x{original_value:02X} -> 0x{new_byte:02X} caused {result['crash_type']} crash"
                                        }
                                        crash_inducing_modifications.append(crash_info)
                                        
                                        # check whether it matches the reference version crash type
                                        normalized_actual_crash_type = self.normalize_crash_type(result["crash_type"])
                                        normalized_ref_crash_type = self.normalize_crash_type(self.ref_crash_type)
                                        
                                        if normalized_actual_crash_type == normalized_ref_crash_type:
                                            triggering_modifications.append(crash_info)
                                            print(f"  ✓ {crash_info['description']} (matches the reference version crash type: {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                                        else:
                                            print(f"  ~ {crash_info['description']} (does not match the reference version crash type: {normalized_actual_crash_type} vs {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
        else:
            # if the file format cannot be parsed, use brute force
            print("cannot parse the file format, using brute force for testing...")
            return self.exhaustive_search()
        
        return {
            "format_aware_triggering_modifications": triggering_modifications,
            "format_aware_all_crash_inducing_modifications": crash_inducing_modifications,
            "target_program": str(target_program)
        }

    def exhaustive_search(self, max_test_bytes: int = 1024) -> Dict:
        """
        brute-force search - test multiple modifications at each byte position
        """
        print(f"Start brute-force search...")
        
        # find the target version executable
        target_program = self.find_executable(self.target_build_dir, "target")
        if not target_program:
            # try to find it in subdirectories
            for subdir in ['sfcommands', 'src', 'bin', 'tools']:
                subdir_path = self.target_build_dir / subdir
                if subdir_path.exists():
                    target_program = self.find_executable(subdir_path, "target")
                    if target_program:
                        break
        
        if not target_program:
            print(f"Error: target version executable not found")
            return {
                "error": "target version executable not found",
                "test_results": []
            }
        
        print(f"Using target program: {target_program}")
        
        triggering_modifications = []  # only record modifications that trigger the same vulnerability
        crash_inducing_modifications = []  # record all crash-inducing modifications
        
        # record the start time
        start_time = time.time()
        
        # set for deduplication that records discovered crash type combinations
        seen_crash_combinations = set()
        
        for offset in range(min(len(self.original_data), max_test_bytes)):
            original_value = self.original_data[offset]
            
            # test multiple possible modification values
            test_values = [1, 2, 3, 255, original_value + 1, original_value ^ 0xFF]
            test_values = [v for v in test_values if 0 <= v <= 255 and v != original_value]
            
            for new_value in test_values:
                modified_data = self.original_data.copy()
                modified_data[offset] = new_value
                
                result = self.run_program_with_sanitizer(target_program, modified_data)
                
                if result["crashed"]:
                    # create an identifier for deduplication, including the offset, crash type and key parts of the stack trace
                    crash_signature = (
                        offset,
                        result["crash_type"],
                        tuple(sorted([frame["function"] for frame in result["stack_trace"][:5]]))  # only consider the first 5 stack frames
                    )
                    
                    if crash_signature not in seen_crash_combinations:
                        seen_crash_combinations.add(crash_signature)
                        
                        # calculate the discovery time
                        current_time = time.time()
                        elapsed_time = current_time - start_time
                        
                        crash_info = {
                            "offset": offset,
                            "original_value": original_value,
                            "new_value": new_value,
                            "crash_type": result["crash_type"],
                            "crash_reason": result["crash_reason"],
                            "stack_trace": result["stack_trace"],
                            "stderr": result["stderr"][:500],  # keep only the first 500 characters
                            "found_time": f"{elapsed_time:.2f}s",  # add the discovery time
                            "description": f"brute-force modification: offset 0x{offset:02X}: 0x{original_value:02X} -> 0x{new_value:02X} caused {result['crash_type']} crash"
                        }
                        crash_inducing_modifications.append(crash_info)
                        
                        # check whether it matches the reference version crash type
                        normalized_actual_crash_type = self.normalize_crash_type(result["crash_type"])
                        normalized_ref_crash_type = self.normalize_crash_type(self.ref_crash_type)
                        
                        if normalized_actual_crash_type == normalized_ref_crash_type:
                            triggering_modifications.append(crash_info)
                            print(f"  ✓ {crash_info['description']} (matches the reference version crash type: {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                        else:
                            print(f"  ~ {crash_info['description']} (does not match the reference version crash type: {normalized_actual_crash_type} vs {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                
                else:
                    # do not record successful execution, because we focus on triggering the vulnerability
                    pass

        return {
            "exhaustive_triggering_modifications": triggering_modifications,
            "exhaustive_all_crash_inducing_modifications": crash_inducing_modifications,
            "target_program": str(target_program)
        }

    def test_single_offset_modifications(self, max_test_bytes: int = 1024) -> Dict:
        """
        test modification at a single offset position
        """
        print(f"Start testing modification at a single offset position...")
        
        # find the target version executable
        target_program = self.find_executable(self.target_build_dir, "target")
        if not target_program:
            # try to find it in subdirectories
            for subdir in ['sfcommands', 'src', 'bin', 'tools']:
                subdir_path = self.target_build_dir / subdir
                if subdir_path.exists():
                    target_program = self.find_executable(subdir_path, "target")
                    if target_program:
                        break
        
        if not target_program:
            print(f"Error: target version executable not found")
            return {
                "error": "target version executable not found",
                "test_results": []
            }
        
        print(f"Using target program: {target_program}")
        
        triggering_modifications = []  # only record modifications that trigger the same vulnerability
        crash_inducing_modifications = []  # record all crash-inducing modifications
        
        # record the start time
        start_time = time.time()
        
        # set for deduplication that records discovered crash type combinations
        seen_crash_combinations = set()
        
        for offset in range(min(len(self.original_data), max_test_bytes)):
            original_value = self.original_data[offset]
            
            # test multiple possible modification values
            test_values = [1, 2, 3, 255, original_value + 1, original_value ^ 0xFF]
            test_values = [v for v in test_values if 0 <= v <= 255 and v != original_value]
            
            for new_value in test_values:
                modified_data = self.original_data.copy()
                modified_data[offset] = new_value
                
                result = self.run_program_with_sanitizer(target_program, modified_data)
                
                if result["crashed"]:
                    # create an identifier for deduplication, including the offset, crash type and key parts of the stack trace
                    crash_signature = (
                        offset,
                        result["crash_type"],
                        tuple(sorted([frame["function"] for frame in result["stack_trace"][:5]]))  # only consider the first 5 stack frames
                    )
                    
                    if crash_signature not in seen_crash_combinations:
                        seen_crash_combinations.add(crash_signature)
                        
                        # calculate the discovery time
                        current_time = time.time()
                        elapsed_time = current_time - start_time
                        
                        crash_info = {
                            "offset": offset,
                            "original_value": original_value,
                            "new_value": new_value,
                            "crash_type": result["crash_type"],
                            "crash_reason": result["crash_reason"],
                            "stack_trace": result["stack_trace"],
                            "stderr": result["stderr"][:500],  # keep only the first 500 characters
                            "found_time": f"{elapsed_time:.2f}s",  # add the discovery time
                            "description": f"single offset: offset 0x{offset:02X}: 0x{original_value:02X} -> 0x{new_value:02X} caused {result['crash_type']} crash"
                        }
                        crash_inducing_modifications.append(crash_info)
                        
                        # check whether it matches the reference version crash type
                        normalized_actual_crash_type = self.normalize_crash_type(result["crash_type"])
                        normalized_ref_crash_type = self.normalize_crash_type(self.ref_crash_type)
                        
                        if normalized_actual_crash_type == normalized_ref_crash_type:
                            triggering_modifications.append(crash_info)
                            print(f"  ✓ {crash_info['description']} (matches the reference version crash type: {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                        else:
                            print(f"  ~ {crash_info['description']} (does not match the reference version crash type: {normalized_actual_crash_type} vs {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                
                else:
                    # do not record successful execution, because we focus on triggering the vulnerability
                    pass

        return {
            "triggering_modifications": triggering_modifications,  # only modifications that trigger the same vulnerability
            "all_crash_inducing_modifications": crash_inducing_modifications,  # all crash-inducing modifications
            "target_program": str(target_program)  # convert to string
        }

    def test_double_offset_modifications(self, max_test_bytes: int = 256) -> Dict:
        """
        test modification at two offset positions
        """
        print(f"Start testing modification at two offset positions...")
        
        # find the target version executable
        target_program = self.find_executable(self.target_build_dir, "target")
        if not target_program:
            # try to find it in subdirectories
            for subdir in ['sfcommands', 'src', 'bin', 'tools']:
                subdir_path = self.target_build_dir / subdir
                if subdir_path.exists():
                    target_program = self.find_executable(subdir_path, "target")
                    if target_program:
                        break
        
        if not target_program:
            print(f"Error: target version executable not found")
            return {
                "error": "target version executable not found",
                "test_results": []
            }
        
        print(f"Using target program: {target_program}")
        
        triggering_modifications = []  # only record modifications that trigger the same vulnerability
        crash_inducing_modifications = []  # record all crash-inducing modifications
        
        # record the start time
        start_time = time.time()
        
        # set for deduplication that records discovered crash type combinations
        seen_crash_combinations = set()
        
        # iterate over two different offset positions
        for offset1 in range(min(len(self.original_data), max_test_bytes)):
            for offset2 in range(offset1 + 1, min(len(self.original_data), max_test_bytes + 10)):
                original_value1 = self.original_data[offset1]
                original_value2 = self.original_data[offset2]
                
                # test several possible modification combinations
                test_combinations = [
                    (original_value1 + 1, original_value2 + 1),
                    (original_value1 ^ 0xFF, original_value2 ^ 0xFF),
                    (1, 1),
                    (255, 255),
                    (original_value1 + 1, original_value2 ^ 0xFF),
                    (original_value1 ^ 0xFF, original_value2 + 1)
                ]
                
                for new_value1, new_value2 in test_combinations:
                    # ensure the new value is within the valid range
                    new_value1 = new_value1 & 0xFF
                    new_value2 = new_value2 & 0xFF
                    
                    # skip cases that are unchanged
                    if new_value1 == original_value1 and new_value2 == original_value2:
                        continue
                    
                    modified_data = self.original_data.copy()
                    modified_data[offset1] = new_value1
                    modified_data[offset2] = new_value2
                    
                    result = self.run_program_with_sanitizer(target_program, modified_data)
                    
                    if result["crashed"]:
                        # create an identifier for deduplication, including the offset, crash type and key parts of the stack trace
                        crash_signature = (
                            offset1,
                            offset2,
                            result["crash_type"],
                            tuple(sorted([frame["function"] for frame in result["stack_trace"][:5]]))  # only consider the first 5 stack frames
                        )
                        
                        if crash_signature not in seen_crash_combinations:
                            seen_crash_combinations.add(crash_signature)
                            
                            # calculate the discovery time
                            current_time = time.time()
                            elapsed_time = current_time - start_time
                            
                            crash_info = {
                                "offset1": offset1,
                                "offset2": offset2,
                                "original_value1": original_value1,
                                "original_value2": original_value2,
                                "new_value1": new_value1,
                                "new_value2": new_value2,
                                "crash_type": result["crash_type"],
                                "crash_reason": result["crash_reason"],
                                "stack_trace": result["stack_trace"],
                                "stderr": result["stderr"][:500],  # keep only the first 500 characters
                                "found_time": f"{elapsed_time:.2f}s",  # add the discovery time
                                "description": f"double offset: offset 0x{offset1:02X},0x{offset2:02X}: (0x{original_value1:02X},0x{original_value2:02X}) -> (0x{new_value1:02X},0x{new_value2:02X}) caused {result['crash_type']} crash"
                            }
                            crash_inducing_modifications.append(crash_info)
                            
                            # check whether it matches the reference version crash type
                            normalized_actual_crash_type = self.normalize_crash_type(result["crash_type"])
                            normalized_ref_crash_type = self.normalize_crash_type(self.ref_crash_type)
                            
                            if normalized_actual_crash_type == normalized_ref_crash_type:
                                triggering_modifications.append(crash_info)
                                print(f"  ✓ {crash_info['description']} (matches the reference version crash type: {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                            else:
                                print(f"  ~ {crash_info['description']} (does not match the reference version crash type: {normalized_actual_crash_type} vs {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                    
                    else:
                        # do not record successful execution, because we focus on triggering the vulnerability
                        pass

        return {
            "double_offset_triggering_modifications": triggering_modifications,  # only modifications that trigger the same vulnerability
            "double_offset_all_crash_inducing_modifications": crash_inducing_modifications,  # all crash-inducing modifications
            "target_program": str(target_program)  # convert to string
        }

    def test_triple_offset_modifications(self, max_test_bytes: int = 128) -> Dict:
        """
        test modification at three offset positions
        """
        print(f"Start testing modification at three offset positions...")
        
        # find the target version executable
        target_program = self.find_executable(self.target_build_dir, "target")
        if not target_program:
            # try to find it in subdirectories
            for subdir in ['sfcommands', 'src', 'bin', 'tools']:
                subdir_path = self.target_build_dir / subdir
                if subdir_path.exists():
                    target_program = self.find_executable(subdir_path, "target")
                    if target_program:
                        break
        
        if not target_program:
            print(f"Error: target version executable not found")
            return {
                "error": "target version executable not found",
                "test_results": []
            }
        
        print(f"Using target program: {target_program}")
        
        triggering_modifications = []  # only record modifications that trigger the same vulnerability
        crash_inducing_modifications = []  # record all crash-inducing modifications
        
        # record the start time
        start_time = time.time()
        
        # set for deduplication that records discovered crash type combinations
        seen_crash_combinations = set()
        
        # iterate over three different offset positions
        for offset1 in range(min(len(self.original_data), max_test_bytes)):
            for offset2 in range(offset1 + 1, min(len(self.original_data), max_test_bytes + 5)):
                for offset3 in range(offset2 + 1, min(len(self.original_data), max_test_bytes + 10)):
                    original_value1 = self.original_data[offset1]
                    original_value2 = self.original_data[offset2]
                    original_value3 = self.original_data[offset3]
                    
                    # test several possible modification combinations
                    test_combinations = [
                        (original_value1 + 1, original_value2 + 1, original_value3 + 1),
                        (original_value1 ^ 0xFF, original_value2 ^ 0xFF, original_value3 ^ 0xFF),
                        (1, 1, 1),
                        (255, 255, 255),
                        (original_value1 + 1, original_value2 ^ 0xFF, original_value3 + 1),
                        (original_value1 ^ 0xFF, original_value2 + 1, original_value3 ^ 0xFF),
                        (original_value1 + 1, original_value2 + 1, original_value3 ^ 0xFF),
                        (original_value1 ^ 0xFF, original_value2 ^ 0xFF, original_value3 + 1)
                    ]
                    
                    for new_value1, new_value2, new_value3 in test_combinations:
                        # ensure the new value is within the valid range
                        new_value1 = new_value1 & 0xFF
                        new_value2 = new_value2 & 0xFF
                        new_value3 = new_value3 & 0xFF
                        
                        # skip cases that are unchanged
                        if new_value1 == original_value1 and new_value2 == original_value2 and new_value3 == original_value3:
                            continue
                        
                        modified_data = self.original_data.copy()
                        modified_data[offset1] = new_value1
                        modified_data[offset2] = new_value2
                        modified_data[offset3] = new_value3
                        
                        result = self.run_program_with_sanitizer(target_program, modified_data)
                        
                        if result["crashed"]:
                            # create an identifier for deduplication, including the offset, crash type and key parts of the stack trace
                            crash_signature = (
                                offset1,
                                offset2,
                                offset3,
                                result["crash_type"],
                                tuple(sorted([frame["function"] for frame in result["stack_trace"][:5]]))  # only consider the first 5 stack frames
                            )
                            
                            if crash_signature not in seen_crash_combinations:
                                seen_crash_combinations.add(crash_signature)
                                
                                # calculate the discovery time
                                current_time = time.time()
                                elapsed_time = current_time - start_time
                                
                                crash_info = {
                                    "offset1": offset1,
                                    "offset2": offset2,
                                    "offset3": offset3,
                                    "original_value1": original_value1,
                                    "original_value2": original_value2,
                                    "original_value3": original_value3,
                                    "new_value1": new_value1,
                                    "new_value2": new_value2,
                                    "new_value3": new_value3,
                                    "crash_type": result["crash_type"],
                                    "crash_reason": result["crash_reason"],
                                    "stack_trace": result["stack_trace"],
                                    "stderr": result["stderr"][:500],  # keep only the first 500 characters
                                    "found_time": f"{elapsed_time:.2f}s",  # add the discovery time
                                    "description": f"triple offset: offset 0x{offset1:02X},0x{offset2:02X},0x{offset3:02X}: (0x{original_value1:02X},0x{original_value2:02X},0x{original_value3:02X}) -> (0x{new_value1:02X},0x{new_value2:02X},0x{new_value3:02X}) caused {result['crash_type']} crash"
                                }
                                crash_inducing_modifications.append(crash_info)
                                
                                # check whether it matches the reference version crash type
                                normalized_actual_crash_type = self.normalize_crash_type(result["crash_type"])
                                normalized_ref_crash_type = self.normalize_crash_type(self.ref_crash_type)
                                
                                if normalized_actual_crash_type == normalized_ref_crash_type:
                                    triggering_modifications.append(crash_info)
                                    print(f"  ✓ {crash_info['description']} (matches the reference version crash type: {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                                else:
                                    print(f"  ~ {crash_info['description']} (does not match the reference version crash type: {normalized_actual_crash_type} vs {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                        
                        else:
                            # do not record successful execution, because we focus on triggering the vulnerability
                            pass

        return {
            "triple_offset_triggering_modifications": triggering_modifications,  # only modifications that trigger the same vulnerability
            "triple_offset_all_crash_inducing_modifications": crash_inducing_modifications,  # all crash-inducing modifications
            "target_program": str(target_program)  # convert to string
        }

    def test_quadruple_offset_modifications(self, max_test_bytes: int = 64) -> Dict:
        """
        test modification at four offset positions
        the first two offset positions are fixed
        """
        print(f"Start testing modification at four offset positions... (the first two offset positions are fixed)")
        
        # find the target version executable
        target_program = self.find_executable(self.target_build_dir, "target")
        if not target_program:
            # try to find it in subdirectories
            for subdir in ['sfcommands', 'src', 'bin', 'tools']:
                subdir_path = self.target_build_dir / subdir
                if subdir_path.exists():
                    target_program = self.find_executable(subdir_path, "target")
                    if target_program:
                        break
        
        if not target_program:
            print(f"Error: target version executable not found")
            return {
                "error": "target version executable not found",
                "test_results": []
            }
        
        print(f"Using target program: {target_program}")
        
        triggering_modifications = []  # only record modifications that trigger the same vulnerability
        crash_inducing_modifications = []  # record all crash-inducing modifications
        
        # record the start time
        start_time = time.time()
        
        # set for deduplication that records discovered crash type combinations
        seen_crash_combinations = set()
        
        # fix the first two offset positions and iterate over two other different offset positions
        # iterate from the third offset
        for offset3 in range(2, min(len(self.original_data), max_test_bytes + 10)):
            for offset4 in range(offset3 + 1, min(len(self.original_data), max_test_bytes + 15)):
                original_value3 = self.original_data[offset3]
                original_value4 = self.original_data[offset4]
                
                # test several possible modification combinations
                test_combinations = [
                    (original_value3 + 1, original_value4 + 1),
                    (original_value3 ^ 0xFF, original_value4 ^ 0xFF),
                    (1, 1),
                    (255, 255),
                    (original_value3 + 1, original_value4 ^ 0xFF),
                    (original_value3 ^ 0xFF, original_value4 + 1)
                ]
                
                for new_value3, new_value4 in test_combinations:
                    # ensure the new value is within the valid range
                    new_value3 = new_value3 & 0xFF
                    new_value4 = new_value4 & 0xFF
                    
                    # skip cases that are unchanged
                    if new_value3 == original_value3 and new_value4 == original_value4:
                        continue
                    
                    modified_data = self.original_data.copy()
                    # keep the first two offset positions unchanged
                    modified_data[0] = self.original_data[0]  # fix the first offset
                    modified_data[1] = self.original_data[1]  # fix the second offset
                    modified_data[offset3] = new_value3
                    modified_data[offset4] = new_value4
                    
                    result = self.run_program_with_sanitizer(target_program, modified_data)
                    
                    if result["crashed"]:
                        # create an identifier for deduplication, including the offset, crash type and key parts of the stack trace
                        crash_signature = (
                            0,  # fixed offset 1
                            1,  # fixed offset 2
                            offset3,
                            offset4,
                            result["crash_type"],
                            tuple(sorted([frame["function"] for frame in result["stack_trace"][:5]]))  # only consider the first 5 stack frames
                        )
                        
                        if crash_signature not in seen_crash_combinations:
                            seen_crash_combinations.add(crash_signature)
                            
                            # calculate the discovery time
                            current_time = time.time()
                            elapsed_time = current_time - start_time
                            
                            crash_info = {
                                "offset1": 0,  # fixed
                                "offset2": 1,  # fixed
                                "offset3": offset3,
                                "offset4": offset4,
                                "original_value1": self.original_data[0],  # fixed
                                "original_value2": self.original_data[1],  # fixed
                                "original_value3": original_value3,
                                "original_value4": original_value4,
                                "new_value1": self.original_data[0],  # fixed
                                "new_value2": self.original_data[1],  # fixed
                                "new_value3": new_value3,
                                "new_value4": new_value4,
                                "crash_type": result["crash_type"],
                                "crash_reason": result["crash_reason"],
                                "stack_trace": result["stack_trace"],
                                "stderr": result["stderr"][:500],  # keep only the first 500 characters
                                "found_time": f"{elapsed_time:.2f}s",  # add the discovery time
                                "description": f"quadruple offset: offset 0x00,0x01,0x{offset3:02X},0x{offset4:02X}: (0x{self.original_data[0]:02X},0x{self.original_data[1]:02X},0x{original_value3:02X},0x{original_value4:02X}) -> (0x{self.original_data[0]:02X},0x{self.original_data[1]:02X},0x{new_value3:02X},0x{new_value4:02X}) caused {result['crash_type']} crash"
                            }
                            crash_inducing_modifications.append(crash_info)
                            
                            # check whether it matches the reference version crash type
                            normalized_actual_crash_type = self.normalize_crash_type(result["crash_type"])
                            normalized_ref_crash_type = self.normalize_crash_type(self.ref_crash_type)
                            
                            if normalized_actual_crash_type == normalized_ref_crash_type:
                                triggering_modifications.append(crash_info)
                                print(f"  ✓ {crash_info['description']} (matches the reference version crash type: {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                            else:
                                print(f"  ~ {crash_info['description']} (does not match the reference version crash type: {normalized_actual_crash_type} vs {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                    
                    else:
                        # do not record successful execution, because we focus on triggering the vulnerability
                        pass

        return {
            "quadruple_offset_triggering_modifications": triggering_modifications,  # only modifications that trigger the same vulnerability
            "quadruple_offset_all_crash_inducing_modifications": crash_inducing_modifications,  # all crash-inducing modifications
            "target_program": str(target_program)  # convert to string
        }

    def test_quintuple_offset_modifications(self, max_test_bytes: int = 32) -> Dict:
        """
        test modification at five offset positions
        the first two offset positions are fixed
        """
        print(f"Start testing modification at five offset positions... (the first two offset positions are fixed)")
        
        # find the target version executable
        target_program = self.find_executable(self.target_build_dir, "target")
        if not target_program:
            # try to find it in subdirectories
            for subdir in ['sfcommands', 'src', 'bin', 'tools']:
                subdir_path = self.target_build_dir / subdir
                if subdir_path.exists():
                    target_program = self.find_executable(subdir_path, "target")
                    if target_program:
                        break
        
        if not target_program:
            print(f"Error: target version executable not found")
            return {
                "error": "target version executable not found",
                "test_results": []
            }
        
        print(f"Using target program: {target_program}")
        
        triggering_modifications = []  # only record modifications that trigger the same vulnerability
        crash_inducing_modifications = []  # record all crash-inducing modifications
        
        # record the start time
        start_time = time.time()
        
        # set for deduplication that records discovered crash type combinations
        seen_crash_combinations = set()
        
        # fix the first two offset positions and iterate over three other different offset positions
        # iterate from the third offset
        for offset3 in range(2, min(len(self.original_data), max_test_bytes + 5)):
            for offset4 in range(offset3 + 1, min(len(self.original_data), max_test_bytes + 10)):
                for offset5 in range(offset4 + 1, min(len(self.original_data), max_test_bytes + 15)):
                    original_value3 = self.original_data[offset3]
                    original_value4 = self.original_data[offset4]
                    original_value5 = self.original_data[offset5]
                    
                    # test several possible modification combinations
                    test_combinations = [
                        (original_value3 + 1, original_value4 + 1, original_value5 + 1),
                        (original_value3 ^ 0xFF, original_value4 ^ 0xFF, original_value5 ^ 0xFF),
                        (1, 1, 1),
                        (255, 255, 255),
                        (original_value3 + 1, original_value4 ^ 0xFF, original_value5 + 1),
                        (original_value3 ^ 0xFF, original_value4 + 1, original_value5 ^ 0xFF),
                        (original_value3 + 1, original_value4 + 1, original_value5 ^ 0xFF),
                        (original_value3 ^ 0xFF, original_value4 ^ 0xFF, original_value5 + 1)
                    ]
                    
                    for new_value3, new_value4, new_value5 in test_combinations:
                        # ensure the new value is within the valid range
                        new_value3 = new_value3 & 0xFF
                        new_value4 = new_value4 & 0xFF
                        new_value5 = new_value5 & 0xFF
                        
                        # skip cases that are unchanged
                        if new_value3 == original_value3 and new_value4 == original_value4 and new_value5 == original_value5:
                            continue
                        
                        modified_data = self.original_data.copy()
                        # keep the first two offset positions unchanged
                        modified_data[0] = self.original_data[0]  # fix the first offset
                        modified_data[1] = self.original_data[1]  # fix the second offset
                        modified_data[offset3] = new_value3
                        modified_data[offset4] = new_value4
                        modified_data[offset5] = new_value5
                        
                        result = self.run_program_with_sanitizer(target_program, modified_data)
                        
                        if result["crashed"]:
                            # create an identifier for deduplication, including the offset, crash type and key parts of the stack trace
                            crash_signature = (
                                0,  # fixed offset 1
                                1,  # fixed offset 2
                                offset3,
                                offset4,
                                offset5,
                                result["crash_type"],
                                tuple(sorted([frame["function"] for frame in result["stack_trace"][:5]]))  # only consider the first 5 stack frames
                            )
                            
                            if crash_signature not in seen_crash_combinations:
                                seen_crash_combinations.add(crash_signature)
                                
                                # calculate the discovery time
                                current_time = time.time()
                                elapsed_time = current_time - start_time
                                
                                crash_info = {
                                    "offset1": 0,  # fixed
                                    "offset2": 1,  # fixed
                                    "offset3": offset3,
                                    "offset4": offset4,
                                    "offset5": offset5,
                                    "original_value1": self.original_data[0],  # fixed
                                    "original_value2": self.original_data[1],  # fixed
                                    "original_value3": original_value3,
                                    "original_value4": original_value4,
                                    "original_value5": original_value5,
                                    "new_value1": self.original_data[0],  # fixed
                                    "new_value2": self.original_data[1],  # fixed
                                    "new_value3": new_value3,
                                    "new_value4": new_value4,
                                    "new_value5": new_value5,
                                    "crash_type": result["crash_type"],
                                    "crash_reason": result["crash_reason"],
                                    "stack_trace": result["stack_trace"],
                                    "stderr": result["stderr"][:500],  # keep only the first 500 characters
                                    "found_time": f"{elapsed_time:.2f}s",  # add the discovery time
                                    "description": f"quintuple offset: offset 0x00,0x01,0x{offset3:02X},0x{offset4:02X},0x{offset5:02X}: (0x{self.original_data[0]:02X},0x{self.original_data[1]:02X},0x{original_value3:02X},0x{original_value4:02X},0x{original_value5:02X}) -> (0x{self.original_data[0]:02X},0x{self.original_data[1]:02X},0x{new_value3:02X},0x{new_value4:02X},0x{new_value5:02X}) caused {result['crash_type']} crash"
                                }
                                crash_inducing_modifications.append(crash_info)
                                
                                # check whether it matches the reference version crash type
                                normalized_actual_crash_type = self.normalize_crash_type(result["crash_type"])
                                normalized_ref_crash_type = self.normalize_crash_type(self.ref_crash_type)
                                
                                if normalized_actual_crash_type == normalized_ref_crash_type:
                                    triggering_modifications.append(crash_info)
                                    print(f"  ✓ {crash_info['description']} (matches the reference version crash type: {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                                else:
                                    print(f"  ~ {crash_info['description']} (does not match the reference version crash type: {normalized_actual_crash_type} vs {normalized_ref_crash_type}) (discovery time: {elapsed_time:.2f}s)")
                        
                        else:
                            # do not record successful execution, because we focus on triggering the vulnerability
                            pass

        return {
            "quintuple_offset_triggering_modifications": triggering_modifications,  # only modifications that trigger the same vulnerability
            "quintuple_offset_all_crash_inducing_modifications": crash_inducing_modifications,  # all crash-inducing modifications
            "target_program": str(target_program)  # convert to string
        }

    def run_analysis(self) -> Dict:
        """
        run the input modification analysis
        """
        print(f"Start analyzing the input file modification strategy...")
        print(f"related variables: {self.related_vars}")
        print(f"crash analysis: {self.crash_analysis}")
        print(f"reference version crash type: {self.ref_crash_type}")
        
        # initialize counter variables
        single_triggering_count = 0
        single_crash_count = 0
        double_triggering_count = 0
        double_crash_count = 0
        triple_triggering_count = 0
        triple_crash_count = 0
        quadruple_triggering_count = 0
        quadruple_crash_count = 0
        quintuple_triggering_count = 0
        quintuple_crash_count = 0
        
        # first try structure-aware fuzzing
        format_aware_results = {}
        if self.file_format_info:
            print(f"\nStart structure-aware fuzzing...")
            format_aware_results = self.format_aware_modifier()
            
            format_aware_triggering_count = len(format_aware_results.get("format_aware_triggering_modifications", []))
            format_aware_crash_count = len(format_aware_results.get("format_aware_all_crash_inducing_modifications", []))
            
            print(f"Structure-aware fuzzing results:")
            print(f"  number of modifications that trigger the same vulnerability: {format_aware_triggering_count}")
            print(f"  number of modifications that cause any crash: {format_aware_crash_count}")
        else:
            format_aware_triggering_count = 0
            format_aware_crash_count = 0
        
        # if structure-aware testing found no matching trigger, continue with other methods
        single_offset_results = {}
        if format_aware_triggering_count == 0:
            # first test modification at a single offset position
            single_offset_results = self.test_single_offset_modifications()
            
            # check the single offset modification results
            single_triggering_count = len(single_offset_results.get("triggering_modifications", []))
            single_crash_count = len(single_offset_results.get("all_crash_inducing_modifications", []))
            
            print(f"\nSingle offset modification results:")
            print(f"  number of modifications that trigger the same vulnerability: {single_triggering_count}")
            print(f"  number of modifications that cause any crash: {single_crash_count}")
        else:
            # if format-aware testing already found a matching trigger, still set the single offset count to 0
            single_triggering_count = 0
            single_crash_count = 0
        
        # if single offset modification cannot achieve the expected effect, test double offset modification
        double_offset_results = {}
        if single_triggering_count == 0 and format_aware_triggering_count == 0:
            print(f"\nSingle offset modification found no matching vulnerability trigger, starting double offset modification test...")
            double_offset_results = self.test_double_offset_modifications()
            
            double_triggering_count = len(double_offset_results.get("double_offset_triggering_modifications", []))
            double_crash_count = len(double_offset_results.get("double_offset_all_crash_inducing_modifications", []))
            
            print(f"Double offset modification results:")
            print(f"  number of modifications that trigger the same vulnerability: {double_triggering_count}")
            print(f"  number of modifications that cause any crash: {double_crash_count}")
        else:
            # if single offset or format-aware testing already found a matching trigger, still set the double offset count to 0
            double_triggering_count = 0
            double_crash_count = 0
        
        # if double offset modification still cannot achieve the expected effect, test triple offset modification
        triple_offset_results = {}
        if double_triggering_count == 0 and format_aware_triggering_count == 0:
            print(f"\nDouble offset modification found no matching vulnerability trigger, starting triple offset modification test...")
            triple_offset_results = self.test_triple_offset_modifications()
            
            triple_triggering_count = len(triple_offset_results.get("triple_offset_triggering_modifications", []))
            triple_crash_count = len(triple_offset_results.get("triple_offset_all_crash_inducing_modifications", []))
            
            print(f"Triple offset modification results:")
            print(f"  number of modifications that trigger the same vulnerability: {triple_triggering_count}")
            print(f"  number of modifications that cause any crash: {triple_crash_count}")
        else:
            # if double offset already found a matching trigger, still set the triple offset count to 0
            triple_triggering_count = 0
            triple_crash_count = 0
        
        # if triple offset modification still cannot achieve the expected effect, test quadruple offset modification
        quadruple_offset_results = {}
        if triple_triggering_count == 0 and format_aware_triggering_count == 0:
            print(f"\nTriple offset modification found no matching vulnerability trigger, starting quadruple offset modification test...")
            quadruple_offset_results = self.test_quadruple_offset_modifications()
            
            quadruple_triggering_count = len(quadruple_offset_results.get("quadruple_offset_triggering_modifications", []))
            quadruple_crash_count = len(quadruple_offset_results.get("quadruple_offset_all_crash_inducing_modifications", []))
            
            print(f"Quadruple offset modification results:")
            print(f"  number of modifications that trigger the same vulnerability: {quadruple_triggering_count}")
            print(f"  number of modifications that cause any crash: {quadruple_crash_count}")
        else:
            # if triple offset already found a matching trigger, still set the quadruple offset count to 0
            quadruple_triggering_count = 0
            quadruple_crash_count = 0
        
        # if quadruple offset modification still cannot achieve the expected effect, test quintuple offset modification
        quintuple_offset_results = {}
        if quadruple_triggering_count == 0 and format_aware_triggering_count == 0:
            print(f"\nQuadruple offset modification found no matching vulnerability trigger, starting quintuple offset modification test...")
            quintuple_offset_results = self.test_quintuple_offset_modifications()
            
            quintuple_triggering_count = len(quintuple_offset_results.get("quintuple_offset_triggering_modifications", []))
            quintuple_crash_count = len(quintuple_offset_results.get("quintuple_offset_all_crash_inducing_modifications", []))
            
            print(f"Quintuple offset modification results:")
            print(f"  number of modifications that trigger the same vulnerability: {quintuple_triggering_count}")
            print(f"  number of modifications that cause any crash: {quintuple_crash_count}")
        else:
            # if quadruple offset already found a matching trigger, still set the quintuple offset count to 0
            quintuple_triggering_count = 0
            quintuple_crash_count = 0
        
        # generate the analysis report
        report = {
            "file_format_info": self.file_format_info,
            "related_variables": self.related_vars,
            "crash_analysis": self.crash_analysis,
            "reference_crash_type": self.ref_crash_type,  # record the actual crash type of the reference version
            "format_aware_results": format_aware_results,
            "single_offset_results": single_offset_results,
            "double_offset_results": double_offset_results,
            "triple_offset_results": triple_offset_results,
            "quadruple_offset_results": quadruple_offset_results,
            "quintuple_offset_results": quintuple_offset_results,
            "summary": {
                "format_aware_triggering_modifications_count": len(format_aware_results.get("format_aware_triggering_modifications", [])),
                "format_aware_all_crash_inducing_modifications_count": len(format_aware_results.get("format_aware_all_crash_inducing_modifications", [])),
                "single_offset_triggering_modifications_count": len(single_offset_results.get("triggering_modifications", [])),
                "single_offset_all_crash_inducing_modifications_count": len(single_offset_results.get("all_crash_inducing_modifications", [])),
                "double_offset_triggering_modifications_count": len(double_offset_results.get("double_offset_triggering_modifications", [])),
                "double_offset_all_crash_inducing_modifications_count": len(double_offset_results.get("double_offset_all_crash_inducing_modifications", [])),
                "triple_offset_triggering_modifications_count": len(triple_offset_results.get("triple_offset_triggering_modifications", [])),
                "triple_offset_all_crash_inducing_modifications_count": len(triple_offset_results.get("triple_offset_all_crash_inducing_modifications", [])),
                "quadruple_offset_triggering_modifications_count": len(quadruple_offset_results.get("quadruple_offset_triggering_modifications", [])),
                "quadruple_offset_all_crash_inducing_modifications_count": len(quadruple_offset_results.get("quadruple_offset_all_crash_inducing_modifications", [])),
                "quintuple_offset_triggering_modifications_count": len(quintuple_offset_results.get("quintuple_offset_triggering_modifications", [])),
                "quintuple_offset_all_crash_inducing_modifications_count": len(quintuple_offset_results.get("quintuple_offset_all_crash_inducing_modifications", [])),
                "format_aware_crash_types_found": list(set([m.get("crash_type") for m in format_aware_results.get("format_aware_all_crash_inducing_modifications", []) if m.get("crash_type")])),
                "single_crash_types_found": list(set([m.get("crash_type") for m in single_offset_results.get("all_crash_inducing_modifications", []) if m.get("crash_type")])),
                "double_crash_types_found": list(set([m.get("crash_type") for m in double_offset_results.get("double_offset_all_crash_inducing_modifications", []) if m.get("crash_type")])),
                "triple_crash_types_found": list(set([m.get("crash_type") for m in triple_offset_results.get("triple_offset_all_crash_inducing_modifications", []) if m.get("crash_type")])),
                "quadruple_crash_types_found": list(set([m.get("crash_type") for m in quadruple_offset_results.get("quadruple_offset_all_crash_inducing_modifications", []) if m.get("crash_type")])),
                "quintuple_crash_types_found": list(set([m.get("crash_type") for m in quintuple_offset_results.get("quintuple_offset_all_crash_inducing_modifications", []) if m.get("crash_type")])),
                "target_program_used": format_aware_results.get("target_program", "Unknown") or single_offset_results.get("target_program", "Unknown")
            }
        }
        
        print(f"\n=== Input modification analysis results ===")
        print(f"reference version crash type: {self.ref_crash_type}")
        print(f"number of format-aware modifications that trigger the same vulnerability: {report['summary']['format_aware_triggering_modifications_count']}")
        print(f"number of single-offset modifications that trigger the same vulnerability: {report['summary']['single_offset_triggering_modifications_count']}")
        print(f"number of double-offset modifications that trigger the same vulnerability: {report['summary']['double_offset_triggering_modifications_count']}")
        print(f"number of triple-offset modifications that trigger the same vulnerability: {report['summary']['triple_offset_triggering_modifications_count']}")
        print(f"number of quadruple-offset modifications that trigger the same vulnerability: {report['summary']['quadruple_offset_triggering_modifications_count']}")
        print(f"number of quintuple-offset modifications that trigger the same vulnerability: {report['summary']['quintuple_offset_triggering_modifications_count']}")
        print(f"number of format-aware modifications that cause any crash: {report['summary']['format_aware_all_crash_inducing_modifications_count']}")
        print(f"number of single-offset modifications that cause any crash: {report['summary']['single_offset_all_crash_inducing_modifications_count']}")
        print(f"number of double-offset modifications that cause any crash: {report['summary']['double_offset_all_crash_inducing_modifications_count']}")
        print(f"number of triple-offset modifications that cause any crash: {report['summary']['triple_offset_all_crash_inducing_modifications_count']}")
        print(f"number of quadruple-offset modifications that cause any crash: {report['summary']['quadruple_offset_all_crash_inducing_modifications_count']}")
        print(f"number of quintuple-offset modifications that cause any crash: {report['summary']['quintuple_offset_all_crash_inducing_modifications_count']}")
        print(f"crash types found by format-aware testing: {report['summary']['format_aware_crash_types_found']}")
        print(f"crash types found by single-offset testing: {report['summary']['single_crash_types_found']}")
        print(f"crash types found by double-offset testing: {report['summary']['double_crash_types_found']}")
        print(f"crash types found by triple-offset testing: {report['summary']['triple_crash_types_found']}")
        print(f"crash types found by quadruple-offset testing: {report['summary']['quadruple_crash_types_found']}")
        print(f"crash types found by quintuple-offset testing: {report['summary']['quintuple_crash_types_found']}")
        
        # show details of modifications that trigger the same vulnerability
        if format_aware_results.get("format_aware_triggering_modifications"):
            print(f"\nDetails of format-aware modifications that trigger the same vulnerability:")
            for mod in format_aware_results["format_aware_triggering_modifications"]:
                print(f"  - {mod['description']} (discovery time: {mod.get('found_time', 'N/A')})")
        
        if single_offset_results.get("triggering_modifications"):
            print(f"\nDetails of single-offset modifications that trigger the same vulnerability:")
            for mod in single_offset_results["triggering_modifications"]:
                print(f"  - {mod['description']} (discovery time: {mod.get('found_time', 'N/A')})")
        
        if double_offset_results.get("double_offset_triggering_modifications"):
            print(f"\nDetails of double-offset modifications that trigger the same vulnerability:")
            for mod in double_offset_results["double_offset_triggering_modifications"]:
                print(f"  - {mod['description']} (discovery time: {mod.get('found_time', 'N/A')})")
        
        if triple_offset_results.get("triple_offset_triggering_modifications"):
            print(f"\nDetails of triple-offset modifications that trigger the same vulnerability:")
            for mod in triple_offset_results["triple_offset_triggering_modifications"]:
                print(f"  - {mod['description']} (discovery time: {mod.get('found_time', 'N/A')})")
        
        if quadruple_offset_results.get("quadruple_offset_triggering_modifications"):
            print(f"\nDetails of quadruple-offset modifications that trigger the same vulnerability:")
            for mod in quadruple_offset_results["quadruple_offset_triggering_modifications"]:
                print(f"  - {mod['description']} (discovery time: {mod.get('found_time', 'N/A')})")
        
        if quintuple_offset_results.get("quintuple_offset_triggering_modifications"):
            print(f"\nDetails of quintuple-offset modifications that trigger the same vulnerability:")
            for mod in quintuple_offset_results["quintuple_offset_triggering_modifications"]:
                print(f"  - {mod['description']} (discovery time: {mod.get('found_time', 'N/A')})")
        
        return report


class RRBackwardAnalysis:
    """
    rr-based reverse debugging analyzer
    Used to precisely locate the input offset positions that affect fork-point variables
    """
    
    def __init__(self, executable_path: str, input_file: str, crash_location: Dict[str, Any]):
        self.executable_path = Path(executable_path)
        self.input_file = Path(input_file)
        self.crash_file = Path(crash_location["file"])
        self.crash_line = int(crash_location["line"])
        self.function = crash_location.get("function", "")
        self.work_dir = Path(tempfile.mkdtemp(prefix="rr_analysis_"))
        
        print(f"Initializing RR reverse analyzer:")
        print(f"  executable: {self.executable_path}")
        print(f"  Input file: {self.input_file}")
        print(f"  crash location: {self.crash_file}:{self.crash_line}")
        print(f"  function: {self.function}")
        print(f"  working directory: {self.work_dir}")

    def run_rr_record(self) -> bool:
        """run the rr record command to record the program execution"""
        print(f"Start rr record...")
        
        # build the rr record command
        cmd = ["rr", "record", "--chaos", "--wait", str(self.executable_path), str(self.input_file)]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode != 0:
                print(f"rr record failed: {result.stderr}")
                return False
            else:
                print(f"rr record succeeded")
                return True
        except subprocess.TimeoutExpired:
            print(f"rr record timed out")
            return False
        except FileNotFoundError:
            print(f"Error: rr command not found, please make sure rr is installed")
            return False

    def analyze_with_rr_replay(self, target_variable: str) -> Dict[str, Any]:
        """
        use rr replay and a GDB script to analyze the data source of the target variable
        """
        print(f"Start rr replay analysis for variable: {target_variable}")
        
        # create the GDB script
        gdb_script = self.create_gdb_script(target_variable)
        script_path = self.work_dir / "gdb_script.gdb"
        with open(script_path, 'w') as f:
            f.write(gdb_script)
        
        # build the rr replay command
        cmd = ["rr", "replay", "--gdb", f"--command={script_path}"]
        
        try:
            # use subprocess.Popen to interact with GDB
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.work_dir
            )
            
            # wait for the GDB script to finish executing
            stdout, stderr = process.communicate(input="quit\n", timeout=180)
            
            if process.returncode != 0:
                print(f"rr replay failed: {stderr}")
                return {"error": stderr}
            
            # parse the GDB output
            analysis_result = self.parse_gdb_output(stdout, target_variable)
            return analysis_result
            
        except subprocess.TimeoutExpired:
            print(f"rr replay timed out")
            return {"error": "Timeout"}
        except Exception as e:
            print(f"rr replay execution error: {e}")
            return {"error": str(e)}

    def create_gdb_script(self, target_variable: str) -> str:
        """
        create a GDB script for reverse debugging analysis
        """
        script = f"""set confirm off
set pagination off
set print pretty on

# set a breakpoint at the crash location
break {self.crash_file}:{self.crash_line}
# if the above does not work, try using the function name
if "{self.function}"
  break {self.function}
end

# run the program
run

# after the program stops, inspect the target variable
print "Target variable: {target_variable}"
print {target_variable}

# set a hardware watchpoint to monitor variable changes
watch {target_variable}

# reverse-execute until the last modification of the variable is found
reverse-continue

# print the code line that modifies the variable
list
print {target_variable}

# continue reverse execution to find more dependencies
reverse-continue

# quit
quit
"""
        return script

    def parse_gdb_output(self, output: str, target_variable: str) -> Dict[str, Any]:
        """
        parse the GDB output and extract input offset position information
        """
        print(f"Parsing GDB output...")
        
        # analyze the memory addresses and input offset information that may be contained in the output
        lines = output.split('\n')
        
        # find lines containing input-file-related information
        input_related_info = []
        memory_addresses = []
        
        for line in lines:
            # find possible memory addresses
            addr_match = re.search(r'0x[0-9a-fA-F]+', line)
            if addr_match:
                memory_addresses.append(addr_match.group())
            
            # find variables that may be related to the input
            if 'input' in line.lower() or 'buffer' in line.lower() or 'data' in line.lower():
                input_related_info.append(line.strip())
        
        # simulated analysis result - in a real implementation, more complex analysis is needed here
        analysis_result = {
            "target_variable": target_variable,
            "variable_address": memory_addresses[:5] if memory_addresses else ["unknown"],
            "input_related_variables": input_related_info,
            "potential_input_offsets": [],  # this needs to be filled in based on the actual rr analysis results
            "analysis_status": "completed",
            "gdb_output_preview": output[:1000]  # keep only the first 1000 characters
        }
        
        # in a real application, we need a more complex method to associate memory addresses with input file offsets
        # This may require:
        # 1. analyze how the program reads the input file (e.g. fread, read, etc.)
        # 2. track the address of the input buffer
        # 3. determine how the value of the target variable is derived from the input buffer
        
        print(f"GDB output analysis complete")
        return analysis_result

    def run_analysis(self, target_variables: List[str]) -> Dict[str, Any]:
        """
        run the full rr reverse analysis
        """
        print(f"Start full rr reverse analysis...")
        
        # first record the execution
        if not self.run_rr_record():
            return {"error": "rr record failed"}
        
        # analyze each target variable
        analysis_results = {}
        for var in target_variables:
            print(f"analyze variable: {var}")
            result = self.analyze_with_rr_replay(var)
            analysis_results[var] = result
        
        # summarize the results
        summary = {
            "crash_location": f"{self.crash_file}:{self.crash_line}",
            "analyzed_variables": list(analysis_results.keys()),
            "individual_results": analysis_results,
            "total_variables_analyzed": len(target_variables),
            "successful_analyses": sum(1 for r in analysis_results.values() if "error" not in r)
        }
        
        print(f"rr reverse analysis complete")
        return summary


class UniversalVulnerabilityAnalyzer:
    def __init__(self, reference_version_path: str, target_version_path: str, 
                 input_file: str, output_file: str, command_args: List[str], 
                 config_module_path: str, result_file_path: str):
        self.reference_version_path = Path(reference_version_path)
        self.target_version_path = Path(target_version_path)
        self.input_file = Path(input_file)
        self.output_file = Path(output_file)
        self.command_args = command_args
        self.config_module_path = Path(config_module_path)
        self.result_file_path = Path(result_file_path)
        
        # load the config module
        self.config = self.load_config_module()
        
        self.work_dir = Path(tempfile.mkdtemp(prefix="vuln_analysis_"))
        self.results_dir = self.work_dir / "results"
        self.results_dir.mkdir(exist_ok=True)
        
        # timing variables
        self.start_time = None
        self.total_time = 0
        self.compile_start_time = None
        self.compile_end_time = None
        self.trace_comparison_start_time = None
        self.trace_comparison_time = 0
        self.fork_point_analysis_start_time = None
        self.fork_point_analysis_time = 0
        self.tracer_analysis_start_time = None
        self.tracer_analysis_time = 0
        self.fork_point_trigger_analysis_start_time = None
        self.fork_point_trigger_analysis_time = 0
        
        # compile settings are loaded from the config file
        self.compile_commands = self.config.COMPILE_COMMANDS
        self.execution_config = getattr(self.config, 'EXECUTION_CONFIG', {})
        self.analysis_config = getattr(self.config, 'ANALYSIS_CONFIG', {})
        
        # define the list of memory allocation functions
        self.memory_allocation_functions = [
            # common memory allocation functions
            "malloc", "calloc", "realloc", "free",
            "valloc", "pvalloc", "memalign", "aligned_alloc",
            
            # libtiff specific
            "_TIFFmalloc", "_TIFFcalloc", "_TIFFrealloc", "_TIFFfree",
            
            # jasper specific
            "jas_malloc", "jas_calloc", "jas_realloc", "jas_free",
            
            # audiofile specific
            "af_malloc", "af_calloc", "af_realloc", "af_free",
            
            # libpng specific
            "png_malloc", "png_calloc", "png_free",
            
            # lame specific
            "lame_malloc", "lame_calloc", "lame_realloc", "lame_free",
            
            # other common memory allocation function variants
            "xmalloc", "xcalloc", "xrealloc", "xstrdup",
            "safe_malloc", "safe_calloc", "safe_realloc",
            "av_malloc", "av_calloc", "av_realloc", "av_free",  # FFmpeg related
            "ff_malloc", "ff_calloc", "ff_realloc", "ff_free",  # FFmpeg related
        ]

    def load_config_module(self):
        """dynamically load the config module"""
        spec = importlib.util.spec_from_file_location("config", self.config_module_path)
        config_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(config_module)
        return config_module

    def start_timer(self):
        """start timing"""
        self.start_time = time.time()

    def stop_timer(self):
        """stop timing"""
        if self.start_time:
            self.total_time = time.time() - self.start_time
            print(f"total time: {self.total_time:.2f}seconds")

    # build system script files, must never be executed as the target program
    NON_PROGRAM_FILES = {
        "configure", "config.status", "config.guess", "config.sub", "libtool",
        "install-sh", "missing", "depcomp", "compile", "ltmain.sh", "test-driver",
        "ar-lib", "aclocal", "automake", "autoconf", "autoreconf"
    }

    @staticmethod
    def _is_elf_executable(file_path: Path) -> bool:
        """determine whether it is a real ELF executable (exclude shell/perl scripts such as configure)"""
        try:
            if not file_path.is_file() or not os.access(file_path, os.X_OK):
                return False
            with open(file_path, 'rb') as f:
                return f.read(4) == b'\x7fELF'
        except Exception:
            return False

    def _run_build(self, src_dir: Path, version_name: str, env: Dict) -> bool:
        """automatically detect the build system and actually complete the compilation (configure/make or cmake/make)"""
        nproc = str(os.cpu_count() or 2)

        # autotools: generate from configure.ac first when configure is missing
        if not (src_dir / "configure").exists() and (src_dir / "configure.ac").exists():
            print(f"[{version_name}] run autoreconf -fi ...")
            r = subprocess.run(["autoreconf", "-fi"], cwd=src_dir,
                               capture_output=True, text=True, env=env)
            if r.returncode != 0:
                print(f"[{version_name}] autoreconf failed: {r.stderr[-500:]}")

        # cmake project (jasper 2.x+: the source tree has its own build/cmake module directory, the build directory must avoid it)
        if (src_dir / "CMakeLists.txt").exists():
            # fill in the cmake template files missing in some tags
            for tpl in ("jasper.pc.in", "jasper.spec.in"):
                tpl_path = src_dir / tpl
                if not tpl_path.exists():
                    tpl_path.write_text("")
            bld = src_dir / "bld"
            bld.mkdir(exist_ok=True)
            r = subprocess.run(
                ["cmake", "..", "-DCMAKE_BUILD_TYPE=Debug",
                 "-DJAS_ENABLE_OPENGL=OFF", "-DJAS_ENABLE_DOC=OFF"],
                cwd=bld, capture_output=True, text=True, env=env)
            if r.returncode != 0:
                print(f"[{version_name}] cmake failed: {r.stderr[-800:]}")
                return False
            r = subprocess.run(["make", "-j", nproc], cwd=bld,
                               capture_output=True, text=True, env=env)
            if r.returncode != 0:
                print(f"[{version_name}] make failed: {r.stderr[-800:]}")
                return False
            return True

        # autotools
        if (src_dir / "configure").exists():
            r = subprocess.run(["sh", "./configure", "--disable-shared"],
                               cwd=src_dir, capture_output=True, text=True, env=env)
            if r.returncode != 0:
                print(f"[{version_name}] configure failed: {r.stderr[-800:]}")
                return False
            r = subprocess.run(["make", "-j", nproc], cwd=src_dir,
                               capture_output=True, text=True, env=env)
            if r.returncode != 0:
                print(f"[{version_name}] make failed: {r.stderr[-800:]}")
                return False
            return True

        print(f"[{version_name}] build system not found (configure/CMakeLists.txt)")
        return False

    def compile_programs(self):
        """compile the reference version and the target version (with debug info)"""
        print("Start compiling the program (with debug info)...")
        self.compile_start_time = time.time()

        # enhance compile flags for rr analysis
        enhanced_compile_flags = {
            "CFLAGS": "-O0 -g -fsanitize=address -fno-omit-frame-pointer -finstrument-functions -Wno-error",
            "CXXFLAGS": "-O0 -g -fsanitize=address -fno-omit-frame-pointer -finstrument-functions -Wno-error -fpermissive",
            "LDFLAGS": "-fsanitize=address -ldl -lm"
        }

        # compile the reference version
        print("compile the reference version...")
        ref_build_dir = self.work_dir / "ref_build"
        shutil.copytree(self.reference_version_path, ref_build_dir)

        # set compile environment variables, including debug flags
        env = os.environ.copy()
        env.update(self.compile_commands["reference"]["compile_flags"])
        # add enhanced debug flags
        env.update(enhanced_compile_flags)

        # run pre-compilation steps
        for cmd in self.compile_commands["reference"]["pre_build"]:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env, cwd=ref_build_dir)
            if result.returncode != 0:
                print(f"Warning: pre-compilation command failed (continuing): {cmd}")

        # actually run the configuration and compilation
        if not self._run_build(ref_build_dir, "reference version", env):
            raise Exception("reference version compilation failed")
        print("reference version compilation complete")

        # compile the target version
        print("compile the target version...")
        target_build_dir = self.work_dir / "target_build"
        shutil.copytree(self.target_version_path, target_build_dir)

        # set compile environment variables, including debug flags
        env = os.environ.copy()
        env.update(self.compile_commands["target"]["compile_flags"])
        # add enhanced debug flags
        env.update(enhanced_compile_flags)

        # run pre-compilation steps
        for cmd in self.compile_commands["target"]["pre_build"]:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, env=env, cwd=target_build_dir)
            if result.returncode != 0:
                print(f"Warning: pre-compilation command failed (continuing): {cmd}")

        # actually run the configuration and compilation
        if not self._run_build(target_build_dir, "target version", env):
            raise Exception("target version compilation failed")
        print("target version compilation complete")

        self.compile_end_time = time.time()
        print(f"Compilation complete, elapsed time: {self.compile_end_time - self.compile_start_time:.2f}seconds")
        return ref_build_dir, target_build_dir

    def build_command(self, program_path: Path, input_file: Path, output_file: Path, args: List[str], version_name: str) -> List[str]:
        """build the execution command according to the config"""
        exec_config = self.execution_config
        
        if exec_config and "command_format" in exec_config:
            # use the command format from the config
            cmd_template = exec_config["command_format"]
            cmd = cmd_template.format(
                program_path=program_path,
                input_file=input_file,
                output_file=output_file
            ).split()
        else:
            # default command format: program path, input file, output file, args...
            cmd = [str(program_path), str(input_file), str(output_file)] + args
        
        return cmd

    def run_with_debug(self, program_path: Path, input_file: Path, 
                      output_file: Path, args: List[str], 
                      trace_file: Path, version_name: str) -> bool:
        """run the program and record debug information"""
        # build the command
        final_cmd = self.build_command(program_path, input_file, output_file, args, version_name)
        
        print(f"execute {version_name} command: {' '.join(final_cmd)}")
        
        # set environment variables
        env = os.environ.copy()
        # add ASan options to ensure clear output when a crash occurs
        env.update({
            "ASAN_OPTIONS": "abort_on_error=1:symbolize=1:print_stats=0:halt_on_error=1",
            "UBSAN_OPTIONS": "abort_on_error=1:symbolize=1"
        })

        try:
            result = subprocess.run(
                final_cmd,
                capture_output=True,
                text=True,
                timeout=60,  # increase the timeout
                env=env
            )
            
            # check whether it crashed - determine based on the return code and error output
            crashed = self._is_crash(result.returncode, result.stderr)
            
            # record trace information
            trace_info = {
                "command": final_cmd,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "crashed": crashed,
                "execution_time": time.time()
            }
            
            with open(trace_file, 'w') as f:
                json.dump(trace_info, f, indent=2)
                
            print(f"{version_name}command execution result: return code={result.returncode}, crashed={crashed}")
            if result.stderr:
                print(f"{version_name}error output: {result.stderr[:500]}...")
            
            return crashed
            
        except subprocess.TimeoutExpired:
            print(f"{version_name}program run timed out")
            # create a trace file for the timeout
            timeout_trace = {
                "command": final_cmd,
                "return_code": -999,  # indicates a timeout
                "stdout": "",
                "stderr": "TIMEOUT",
                "crashed": False,
                "execution_time": time.time()
            }
            with open(trace_file, 'w') as f:
                json.dump(timeout_trace, f, indent=2)
            return False
        except Exception as e:
            print(f"error executing {version_name} command: {e}")
            # create an error trace file
            error_trace = {
                "command": final_cmd,
                "return_code": -998,  # indicates an execution error
                "stdout": "",
                "stderr": str(e),
                "crashed": False,
                "execution_time": time.time()
            }
            with open(trace_file, 'w') as f:
                json.dump(error_trace, f, indent=2)
            return False

    def _is_crash(self, return_code: int, stderr: str) -> bool:
        """determine whether it crashed - improved judgment logic"""
        # first check the return code - a negative number usually indicates exit caused by a signal
        if return_code < 0:
            # -6 corresponds to SIGABRT (abort signal), which is typical of ASan crashes
            if return_code == -6:  # SIGABRT
                return True
            # -11 corresponds to SIGSEGV (segmentation fault)
            if return_code == -11:  # SIGSEGV
                return True
            # -9 corresponds to SIGKILL
            if return_code == -9:  # SIGKILL
                return True
            # -7 corresponds to SIGBUS (bus error)
            if return_code == -7:  # SIGBUS
                return True
            # -4 corresponds to SIGILL (illegal instruction)
            if return_code == -4:  # SIGILL
                return True
            # other negative numbers usually also indicate abnormal termination
            return True
        
        # check whether there are explicit crash keywords
        crash_keywords = [
            "Segmentation fault", "SEGV", "Aborted", "SIGSEGV", "SIGABRT",
            "AddressSanitizer", "heap-buffer-overflow", "stack-buffer-overflow", 
            "use-after-free", "double-free", "Killed", "Floating point exception",
            "Bus error", "Illegal instruction", "Core dumped", "assertion failed",
            "==ERROR:", "ABORTING", "FPE", "floating-point-exception"
        ]
        
        for keyword in crash_keywords:
            if keyword.lower() in stderr.lower():
                return True
        
        # special check: if stderr contains crash-related keywords
        crash_indicators = [
            "segmentation fault", "SEGV", "aborted", "asan", 
            "heap-buffer", "stack-buffer", "use-after-free", 
            "double-free", "killed", "bus error", "illegal instruction",
            "==ERROR:", "ABORTING", "FPE", "floating-point-exception",
            "heap-use-after-free", "container-overflow", "global-buffer-overflow"
        ]
        for indicator in crash_indicators:
            if indicator in stderr.lower():
                return True
        
        # check whether it is just an error message rather than a crash
        error_indicators = [
            "Error", "Failed", "Warning", "invalid", "incorrect", "expecting", 
            "missing", "no space", "integer overflow", "allocate memory"
        ]
        
        # if there are only error indicator words and no crash indicator words, it may just be normal program error handling
        has_error = any(indicator.lower() in stderr.lower() for indicator in error_indicators)
        has_crash = any(indicator.lower() in stderr.lower() for indicator in crash_indicators)
        
        # if there are both error and crash indicator words, treat it as a crash
        # if there are only errors and no crash indicator words, treat it as normal error handling
        if has_error and not has_crash:
            return False
        
        # check the ASan output pattern (error reports starting with ==)
        if re.search(r'==\d+==ERROR:', stderr):
            return True
        
        # if the return code is non-zero but there are no obvious crash signs, further judgment is needed
        return return_code != 0

    def find_executable_by_config(self, build_dir: Path, version_name: str) -> Optional[Path]:
        """find the executable according to the config"""
        exec_config = self.execution_config

        if exec_config and "program_name" in exec_config:
            program_name = exec_config["program_name"]

            # if a build directory pattern is configured, search under that pattern first
            if "build_dir_pattern" in exec_config:
                build_pattern = exec_config["build_dir_pattern"]
                search_path = build_dir / build_pattern.lstrip('/')
                if search_path.exists():
                    for root, dirs, files in os.walk(search_path):
                        for file in files:
                            file_path = Path(root) / file
                            if file == program_name and os.access(file_path, os.X_OK):
                                return file_path
            # not found in the pattern directory (or no pattern configured): search the entire build directory
            best_match = None
            for root, dirs, files in os.walk(build_dir):
                dirs[:] = [d for d in dirs if d not in ('.git', 'test', 'tests', 'contrib')]
                for file in files:
                    if file == program_name:
                        file_path = Path(root) / file
                        if os.access(file_path, os.X_OK):
                            # prefer to return an ELF binary rather than a script
                            if self._is_elf_executable(file_path):
                                return file_path
                            if best_match is None:
                                best_match = file_path
            return best_match

        return None

    def find_executable(self, build_dir: Path, version_name: str = "") -> Optional[Path]:
        """find the compiled executable"""
        # first try to find it according to the config
        executable = self.find_executable_by_config(build_dir, version_name)
        if executable:
            return executable
        
        # if no program name is specified in the config, use the default search method
        # first try to find executables with specific names
        possible_names = ["sfconvert", "audiofile", "afile", "convert", "main", "program", "imginfo", "tiffcrop", "tiffcp"]
        
        for name in possible_names:
            exe_path = build_dir / name
            if exe_path.is_file() and os.access(exe_path, os.X_OK):
                return exe_path
        
        # if the specific names are not found, search all executables (accept only ELF binaries, exclude configure and other scripts)
        for root, dirs, files in os.walk(build_dir):
            dirs[:] = [d for d in dirs if d not in ('.git', 'test', 'tests', 'contrib')]
            for file in files:
                if file in self.NON_PROGRAM_FILES:
                    continue
                file_path = Path(root) / file
                if self._is_elf_executable(file_path):
                    return file_path
        return None

    def record_execution_traces(self):
        """record the execution traces of the two versions"""
        print("Start recording execution traces...")
        
        ref_build_dir, target_build_dir = self.compile_programs()
        
        # find the compiled program
        ref_program = self.find_executable(ref_build_dir, "reference")
        target_program = self.find_executable(target_build_dir, "target")
        
        # if it is not found in the default directory, try searching in the root directory
        if not ref_program:
            ref_program = self.find_executable(ref_build_dir, "reference")
        if not target_program:
            target_program = self.find_executable(target_build_dir, "target")
        
        if not ref_program or not target_program:
            raise Exception("compiled executable not found")
        
        print(f"reference version program: {ref_program}")
        print(f"target version program: {target_program}")
        
        # record the reference version trace
        ref_trace_file = self.results_dir / "ref_trace.json"
        ref_crashed = self.run_with_debug(
            ref_program, self.input_file, self.output_file, 
            self.command_args, ref_trace_file, "reference version"
        )
        
        # record the target version trace
        target_trace_file = self.results_dir / "target_trace.json"
        target_crashed = self.run_with_debug(
            target_program, self.input_file, self.output_file, 
            self.command_args, target_trace_file, "target version"
        )
        
        # read the trace data
        with open(ref_trace_file) as f:
            self.ref_trace = json.load(f)
        with open(target_trace_file) as f:
            self.target_trace = json.load(f)
        
        print(f"reference version crashed: {ref_crashed}")
        print(f"target version crashed: {target_crashed}")
        
        # save the build directory information
        self.ref_build_dir = ref_build_dir
        self.target_build_dir = target_build_dir
        
        return ref_crashed, target_crashed

    def extract_crash_type(self, stderr: str) -> str:
        """extract the crash type"""
        crash_types = [
            "heap-buffer-overflow",
            "stack-buffer-overflow", 
            "global-buffer-overflow",
            "use-after-free",
            "double-free",
            "SEGV",
            "detected memory leaks",
            "ABRT",
            "stack-overflow",
            "floating-point-exception",
            "divide-by-zero",
            "segmentation fault",
            "bus error",
            "illegal instruction"
        ]
        
        for crash_type in crash_types:
            if crash_type in stderr.lower():
                return crash_type.replace('-', '_').replace(' ', '_')
        
        # check whether it is a crash reported by AddressSanitizer
        if "AddressSanitizer" in stderr:
            # try to extract the specific crash type from the AddressSanitizer report
            asan_patterns = [
                r"heap-buffer-overflow",
                r"stack-buffer-overflow",
                r"global-buffer-overflow", 
                r"use-after-free",
                r"double-free",
                r"SEGV",
                r"heap-use-after-free",
                r"container-overflow"
            ]
            for pattern in asan_patterns:
                if re.search(pattern, stderr, re.IGNORECASE):
                    return pattern.replace('-', '_')
        
        return "unknown"

    def extract_detailed_stack_trace(self, stderr: str) -> List[Dict[str, str]]:
        """extract detailed stack trace information, including file and line numbers"""
        lines = stderr.split('\n')
        stack_trace = []
        
        # find the start marker of the ASAN stack trace
        for line in lines:
            line = line.strip()
            
            # check whether it is an ASAN stack line (format: #number 0xaddress in function_name file:line)
            asan_match = re.match(r'#(\d+) 0x[0-9a-fA-F]+ in (.*?)(?:\s+\((.*)\))?$', line)
            if asan_match:
                frame_num = asan_match.group(1)
                func_info = asan_match.group(2).strip()
                
                # extract the function name
                func_name_match = re.search(r'([^(]+)', func_info)
                if func_name_match:
                    func_name = func_name_match.group(1).strip()
                else:
                    func_name = func_info
                
                # extract the file and line number information
                file_line = ""
                if asan_match.group(3):  # there is information inside parentheses
                    file_line = asan_match.group(3).strip()
                else:
                    # try to extract file:line from the function information
                    file_line_match = re.search(r'(/[^:]+:\d+)', func_info)
                    if file_line_match:
                        file_line = file_line_match.group(1)
                
                stack_frame = {
                    "frame": int(frame_num),
                    "function": func_name,
                    "file_line": file_line,
                    "raw_line": line
                }
                stack_trace.append(stack_frame)
        
        return stack_trace

    def extract_execution_path_from_stderr(self, stderr: str) -> List[str]:
        """
        extract the execution path (function call sequence) from stderr
        supports multiple formats:
        - ASan stack frame: #0 0x... in func_name ...
        - custom debug output: "Entering function X at file.c:123"
        - instrument-functions output (if enabled)
        """
        execution_path = []
        lines = stderr.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # 1. ASan stack frames (from bottom to top, but we record them in order)
            asan_match = re.match(r'#\d+\s+0x[0-9a-fA-F]+\s+in\s+([^(]+)', line)
            if asan_match:
                func = asan_match.group(1).strip()
                if func and not func.startswith('__') and 'asan' not in func.lower():
                    execution_path.append(func)
                continue
                
            # 2. custom debug logs (common patterns)
            # e.g., "DEBUG: read_header called", "Processing chunk at offset 100"
            debug_patterns = [
                r'(?:entering|calling|invoking|processing|reading|writing|parsing)\s+([A-Za-z_][A-Za-z0-9_:]*)',
                r'([A-Za-z_][A-Za-z0-9_:<>,\s]*::[A-Za-z_][A-Za-z0-9_:<>,\s]*)',
                r'\b([A-Za-z_][A-Za-z0-9_]{3,})\s+(?:at|in)\s+[^:]+:\d+'
            ]
            for pattern in debug_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    func = match.group(1).strip()
                    if len(func) > 3 and not any(kw in func.lower() for kw in ['error', 'warning', 'debug', 'log']):
                        execution_path.append(func)
                    break
                    
        # deduplicate but preserve order (adjacent duplicates may be recursion)
        cleaned = []
        for i, f in enumerate(execution_path):
            if i == 0 or f != execution_path[i-1]:
                cleaned.append(f)
        return cleaned

    def extract_execution_path(self, stderr: str) -> List[str]:
        """extract the execution path information from stderr"""
        lines = stderr.split('\n')
        execution_path = []
        
        # find function call information (possibly from debug output)
        for line in lines:
            line = line.strip()
            # find function call patterns, such as "function_name at file:line"
            func_call_match = re.search(r'([A-Za-z_][A-Za-z0-9_～:<>]*\s+at\s+[^:]+:\d+)', line)
            if func_call_match:
                execution_path.append(func_call_match.group(1))
        
        return execution_path

    def find_memory_allocation_frames(self, stack_trace: List[Dict]) -> List[Dict]:
        """
        find memory-allocation-related frames from the stack trace
        """
        memory_frames = []
        
        for frame in stack_trace:
            func_name = frame['function']
            
            # check whether it is a memory allocation function
            for mem_func in self.memory_allocation_functions:
                if mem_func in func_name:
                    memory_frames.append(frame)
                    break  # finding one is enough
        
        return memory_frames

    def _capture_function_trace(self, cmd: List[str], timeout: int = 180) -> List[str]:
        """use functracer.so to capture the function entry sequence from -finstrument-functions"""
        import tempfile
        out_file = tempfile.mktemp(prefix="functrace_", suffix=".log")
        env = os.environ.copy()
        # ASAN requires its runtime to be loaded first, so preload libasan as well and put it first
        try:
            r = subprocess.run(["gcc", "-print-file-name=libasan.so"],
                               capture_output=True, text=True)
            libasan = r.stdout.strip()
        except Exception:
            libasan = ""
        preloads = [p for p in [libasan if "libasan" in libasan else "", 
                                str(Path(__file__).parent / "functracer.so")] if p]
        env.update({
            "LD_PRELOAD": ":".join(preloads),
            "FUNC_TRACE_OUT": out_file,
            "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1",
        })
        try:
            subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            pass
        seq = []
        base_map = {}          # module base address -> binary path
        last_module = None     # the module path declared by the most recent M line
        events = []            # (dir, name) or (dir, ('local', binpath, offset))
        try:
            with open(out_file) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == 'M':
                        try:
                            mpath = parts[2]
                            base_map[int(parts[1], 16)] = mpath
                            last_module = mpath
                        except (IndexError, ValueError):
                            pass
                    elif len(parts) == 3 and parts[0] in ('>', '<') and parts[1].startswith('@'):
                        try:
                            base = int(parts[1][1:], 16)
                            events.append((parts[0], ('local', base_map.get(base), int(parts[2], 16))))
                        except ValueError:
                            continue
                    elif len(parts) == 2 and parts[0] in ('>', '<'):
                        tok = parts[1]
                        if tok.startswith('@'):
                            # local symbol event (fallback when there is no M line): resolve using the most recently declared module
                            try:
                                events.append((parts[0], ('local', last_module, int(tok[1:], 16))))
                            except ValueError:
                                pass
                        else:
                            events.append((parts[0], tok))
        except FileNotFoundError:
            return []
        finally:
            try:
                os.unlink(out_file)
            except Exception:
                pass

        # resolve local symbols: resolve offline per module using the nm symbol table
        import bisect
        sym_tables = {}

        def resolve(binpath, offset):
            if not binpath or not os.path.exists(binpath):
                return None
            if binpath not in sym_tables:
                syms = []
                try:
                    r = subprocess.run(["nm", "--defined-only", "-n", binpath],
                                       capture_output=True, text=True)
                    for l in r.stdout.split('\n'):
                        ps = l.split(maxsplit=2)
                        if len(ps) == 3 and all(c in '0123456789abcdef' for c in ps[0]):
                            syms.append((int(ps[0], 16), ps[2]))
                except Exception:
                    pass
                sym_tables[binpath] = syms
            syms = sym_tables[binpath]
            if not syms:
                return None
            i = bisect.bisect_right([s[0] for s in syms], offset) - 1
            if i >= 0 and offset - syms[i][0] < 65536:
                return syms[i][1].split('(')[0]
            return None

        resolved = 0
        all_events = []
        for d, tok in events:
            if isinstance(tok, tuple):
                name = resolve(tok[1], tok[2])
                if not name:
                    continue
                resolved += 1
            else:
                name = tok
            if name.startswith('__') or 'asan' in name.lower():
                continue
            all_events.append((d, name))
            if d == '>':
                if not seq or seq[-1] != name:   # collapse adjacent duplicates (recursive/loop calls)
                    seq.append(name)

        print(f"Function trace: {len(seq)} call sites ({resolved} local symbols resolved) ({cmd[0]})")
        return seq, all_events

    def find_fork_point_v2(self) -> Dict:
        """
        new fork-point localization:
        Step 1: cross-version function-level alignment (rename/merge/split)
        Step 2: statement-level alignment within the last aligned function (lldb-trace approach)
        """
        result = {}
        try:
            from function_aligner import (FunctionAligner,
                                          statement_align_with_lldb,
                                          align_statements)
        except Exception as e:
            print(f"[v2] unable to import function_aligner: {e}")
            return result

        ref_cmd = self.ref_trace.get("command") or []
        tgt_cmd = self.target_trace.get("command") or []
        if not ref_cmd or not tgt_cmd:
            return result

        # ---- Step 1: function-level alignment ----
        ref_seq, ref_events = self._capture_function_trace(ref_cmd)
        tgt_seq, tgt_events = self._capture_function_trace(tgt_cmd)
        if len(ref_seq) < 2 or len(tgt_seq) < 2:
            print("[v2] function trace too short, skipping function-level alignment")
            return result

        # rebuild the real call graph of the two versions from the paired enter/exit events
        from function_aligner import build_call_graph
        ref_graph = build_call_graph(ref_events)
        tgt_graph = build_call_graph(tgt_events)

        try:
            aligner = FunctionAligner(
                str(self.reference_version_path),
                str(self.target_version_path),
                ref_seq, tgt_seq,
                ref_graph=ref_graph, tgt_graph=tgt_graph)
            align_stats = aligner.align()
        except Exception as e:
            print(f"[v2] function-level alignment failed: {e}")
            return result

        result["function_alignment"] = align_stats

        # ---- Last aligned function (near the end of the trace) ----
        pair = aligner.last_aligned_pair()
        if not pair:
            print("[v2] no cross-version aligned function pair found")
            return result
        ref_func, tgt_func = pair
        print(f"[v2] last aligned function pair: ref:{ref_func} <-> target:{tgt_func}")
        result["last_aligned_pair"] = {"ref": ref_func, "target": tgt_func}

        # ---- Step 2: statement-level alignment (starting at the function entry) ----
        ref_stmt = statement_align_with_lldb(ref_cmd[0], ref_func, ref_cmd[1:])
        tgt_stmt = statement_align_with_lldb(tgt_cmd[0], tgt_func, tgt_cmd[1:])
        for tag, s in (("ref", ref_stmt), ("target", tgt_stmt)):
            if "error" in s:
                print(f"[v2] lldb statement-level tracing failed({tag}): {s['error']}")
            else:
                print(f"[v2] statement-level trace({tag}): {len(s['lines'])} lines, "
                      f"{'truncated' if s['truncated'] else 'complete'}")
        result["statement_traces"] = {
            "ref": {k: v for k, v in ref_stmt.items() if k != 'lines'},
            "target": {k: v for k, v in tgt_stmt.items() if k != 'lines'},
        }

        if "lines" in ref_stmt and "lines" in tgt_stmt and ref_stmt["lines"] and tgt_stmt["lines"]:
            from function_aligner import build_source_index
            ref_idx = build_source_index(str(self.reference_version_path))
            tgt_idx = build_source_index(str(self.target_version_path))
            sa = align_statements(ref_stmt["lines"], tgt_stmt["lines"], ref_idx, tgt_idx)
            result["statement_alignment"] = sa
            if sa.get("fork_statement"):
                fs = sa["fork_statement"]
                print(f"[v2] statement-level fork: ref {[l['file']+':'+str(l['line']) for l in fs['ref_gap_statements']]} vs "
                      f"target {[l['file']+':'+str(l['line']) for l in fs['target_gap_statements']]}")
            else:
                print("[v2] statement-level fully aligned, no statement fork")
        elif "lines" in ref_stmt and ref_stmt["lines"] and ("error" in tgt_stmt or not tgt_stmt.get("lines")):
            # when target version tracing fails, fall back to static line alignment
            rf = aligner.ref_funcs.get(ref_func)
            tf = aligner.tgt_funcs.get(tgt_func)
            if rf and tf:
                from difflib import SequenceMatcher
                sm = SequenceMatcher(None,
                                     [l.strip() for l in rf.body.split('\n') if l.strip()],
                                     [l.strip() for l in tf.body.split('\n') if l.strip()])
                gaps = []
                prev_r = prev_t = 0
                for b in sm.get_matching_blocks():
                    if b.size == 0:
                        break
                    if b.a > prev_r or b.b > prev_t:
                        gaps.append({
                            "ref_lines": rf.body.split('\n')[prev_r:b.a],
                            "target_lines": tf.body.split('\n')[prev_t:b.b],
                            "ref_start_line": rf.line + prev_r,
                            "target_start_line": tf.line + prev_t,
                        })
                        break
                    prev_r, prev_t = b.a + b.size, b.b + b.size
                result["static_statement_diff"] = gaps[:1]

        # ====== Summarize key fork-point positions ======
        key_fork = self._summarize_key_fork_point(aligner, ref_seq, tgt_seq, result)
        if key_fork:
            result["key_fork_point"] = key_fork
        return result

    def _summarize_key_fork_point(self, aligner, ref_seq, tgt_seq, v2_result) -> Optional[Dict]:
        """distill key fork-point positions from the function-level + statement-level alignment results"""
        def lookup_tgt(r):
            if r in aligner.rename_map:
                return aligner.rename_map[r]
            if r in aligner.split_map:
                return aligner.split_map[r][-1]
            return None

        # ---- Function level: search backward from the end of the trace for the first function that cannot be aligned ----
        func_level = None
        tgt_set = set(tgt_seq)
        for i, r in enumerate(reversed(ref_seq)):
            idx_ref = len(ref_seq) - 1 - i
            t = lookup_tgt(r)
            merged_group = None
            for tg, group in aligner.merge_map.items():
                if r in group:
                    merged_group = tg
                    break
            ok = (t and t in tgt_set) or (merged_group and merged_group in tgt_set)
            if not ok:
                ctx = ref_seq[max(0, idx_ref - 2): idx_ref + 2]
                func_level = {
                    "description": f"function {r} executes near the end of the reference version trace, but there is no corresponding (aligned) function in the target version trace",
                    "ref_function": r,
                    "ref_position_from_end": i,
                    "ref_context": ctx,
                    "note": "after this point the behavior of the two versions diverges",
                }
                break

        # ---- Statement level ----
        stmt_level = None
        sa = v2_result.get("statement_alignment") or {}
        fs = sa.get("fork_statement")
        if fs:
            ref_s = fs["ref_gap_statements"][:3]
            tgt_s = fs["target_gap_statements"][:3]
            ref_loc = f"{ref_s[0]['file']}:{ref_s[0]['line']}" if ref_s else None
            tgt_loc = f"{tgt_s[0]['file']}:{tgt_s[0]['line']}" if tgt_s else None
            stmt_level = {
                "ref_location": ref_loc,
                "target_location": tgt_loc,
                "ref_statements": [f"{s['file']}:{s['line']}  {s.get('code','')}" for s in ref_s],
                "target_statements": [f"{s['file']}:{s['line']}  {s.get('code','')}" for s in tgt_s],
            }
        elif v2_result.get("static_statement_diff"):
            sd = v2_result["static_statement_diff"][0]
            stmt_level = {
                "ref_location": f"{sd.get('ref_start_line')}",
                "target_location": f"{sd.get('target_start_line')}",
                "ref_statements": sd.get("ref_lines", [])[:3],
                "target_statements": sd.get("target_lines", [])[:3],
                "note": "static source code difference (dynamic statement tracing unavailable)",
            }

        pair = v2_result.get("last_aligned_pair") or {}
        summary_parts = []
        if func_level:
            summary_parts.append(f"function-level fork: {func_level['ref_function']}")
        if pair:
            summary_parts.append(f"last aligned function: ref:{pair.get('ref')} <-> target:{pair.get('target')}")
        if stmt_level and stmt_level.get("ref_location"):
            summary_parts.append(f"statement-level fork: ref {stmt_level['ref_location']} vs target {stmt_level['target_location']}")
        summary = "; ".join(summary_parts) if summary_parts else "no clear fork point found"

        key_fork = {
            "summary": summary,
            "function_level": func_level,
            "statement_level": stmt_level,
            "last_aligned_pair": pair,
        }
        print("\n" + "=" * 60)
        print("★ Key fork-point positions")
        print("=" * 60)
        print(f"  {summary}")
        if func_level:
            print(f"  Function level: the reference version executes near the end of the trace {func_level['ref_function']}, "
                  f"the target version has no aligned function (position: from the trace end {func_level['ref_position_from_end']})")
        if stmt_level:
            for s in stmt_level.get("ref_statements", [])[:3]:
                print(f"    ref   {s}")
            for s in stmt_level.get("target_statements", [])[:3]:
                print(f"    target {s}")
        print("=" * 60 + "\n")
        return key_fork

    def find_fork_point(self) -> Optional[Dict]:
        """
        compare the execution traces of the two versions to find the fork point
        optimization: if the fork point is inside a memory allocation function, choose the statement that calls the memory allocation function as the fork point
        """
        print("Comparing the execution traces of the two versions to find the fork point...")

        # ====== New version: first do cross-version function-level alignment + statement-level alignment ======
        try:
            v2 = self.find_fork_point_v2()
            if v2:
                self.v2_alignment_results = v2
        except Exception as e:
            print(f"[v2] alignment flow exception (does not affect the original analysis): {e}")

        ref_stderr = self.ref_trace.get("stderr", "")
        target_stderr = self.target_trace.get("stderr", "")
        
        print(f"reference version stderr length: {len(ref_stderr)}")
        print(f"target version stderr length: {len(target_stderr)}")
        
        # check the crash status
        ref_crashed = self.ref_trace.get("crashed", False)
        target_crashed = self.target_trace.get("crashed", False)
        
        # Case 1: reference version crashes, target version does not (the target version is the old version and does not reach the vulnerable code)
        if ref_crashed and not target_crashed:
            print("reference version crashes, target version runs normally - use the reference version crash stack information to find a way to trigger a crash in the target version")
            
            # extract the crash stack information of the reference version
            ref_stack = self.extract_detailed_stack_trace(ref_stderr)
            ref_crash_type = self.extract_crash_type(ref_stderr)
            
            if ref_stack:
                # filter out the stack frames inside sanitizer to find the crash point in user code
                user_stack = self.filter_user_code_stack(ref_stack)
                
                if user_stack:
                    # check whether it crashed inside a memory allocation function; if so, find the location that calls that function
                    memory_frames = self.find_memory_allocation_frames(user_stack)
                    
                    if memory_frames:
                        # find the non-memory-allocation function call closest to the crash point
                        crash_function = None
                        for frame in user_stack:
                            frame_func = frame['function']
                            is_memory_func = any(mem_func in frame_func for mem_func in self.memory_allocation_functions)
                            
                            if not is_memory_func:
                                crash_function = frame
                                break
                        
                        if crash_function is None:
                            # if all frames are memory allocation functions, use the first non-memory-allocation function (if there is none, use the last one)
                            crash_function = user_stack[-1]
                    else:
                        # no memory allocation function, directly use the first user code function
                        crash_function = user_stack[0]
                    
                    crash_location = crash_function['file_line']
                    
                    # parse the crash location
                    parts = crash_location.rsplit(':', 1)
                    if len(parts) >= 2:
                        try:
                            crash_file = Path(parts[0])
                            crash_line = int(parts[1])
                            
                            crash_info = {
                                "type": "reference_crash_target_runs",
                                "scenario": "ref_crashes_target_runs_different_paths",
                                "ref_crash_type": ref_crash_type,
                                "ref_crash_function": crash_function,
                                "ref_stack": [frame['raw_line'] for frame in ref_stack],
                                "user_stack": [frame['raw_line'] for frame in user_stack],
                                "crash_location": {
                                    "file": str(crash_file),  # convert to string
                                    "line": crash_line,
                                    "function": crash_function.get('function', 'unknown')
                                },
                                "target_crashed": target_crashed,
                                "difference": f"ref_crashes_at_{crash_function['function']}_{crash_function['file_line']}_target_runs_normally",
                                "analysis": f"the reference version crashes in function {crash_function['function']} , the target version did not crash, so the input file must be modified to make the target version crash as well",
                                "memory_allocation_context": memory_frames  # add the memory allocation context information
                            }
                            self.fork_point = crash_info
                            print(f"✅ found the reference version crash point: {crash_function['function']} at {crash_function['file_line']}")
                            
                            # now use a new approach: analyze the crash-point-related variables, then test modifications in the input file
                            print("Start analyzing crash-point-related variables...")
                            crash_location_info = crash_info["crash_location"]
                            
                            # use UniversalTracerAnalyzer to analyze the crash point
                            tracer_analyzer = UniversalTracerAnalyzer(
                                str(self.reference_version_path),
                                str(self.target_version_path), 
                                str(self.input_file),
                                crash_location_info,
                                str(self.target_build_dir),  # new parameter
                                str(self.ref_build_dir),      # new parameter
                                self.execution_config         # new parameter
                            )
                            
                            # run the analysis to obtain the related variables
                            crash_analysis = tracer_analyzer.analyze_crash_code()
                            related_vars = tracer_analyzer.find_related_variables(tracer_analyzer.read_crash_source_code())
                            
                            print(f"crash-point-related variables: {related_vars}")
                            
                            # create the input modification analyzer
                            print("Start analyzing the input file modification strategy...")
                            input_modifier = InputModifierAnalyzer(
                                str(self.target_build_dir),
                                str(self.input_file),
                                related_vars,
                                crash_analysis,
                                self.execution_config,
                                ref_crash_type  # pass the actual crash type of the reference version
                            )
                            
                            # run the input modification analysis
                            modification_results = input_modifier.run_analysis()
                            
                            # add the modification results to the fork point information
                            crash_info["input_modification_analysis"] = modification_results
                            
                            return crash_info
                        except ValueError:
                            print(f"unable to parse the crash location: {crash_location}")
                    else:
                        print(f"unable to parse the crash location: {crash_location}")
                else:
                    print("the reference version crashed but there is no usable user code stack information, using the raw stack information")
                    crash_function = ref_stack[0]
                    crash_location = crash_function['file_line']
                    
                    # try to parse the crash location
                    parts = crash_location.rsplit(':', 1)
                    if len(parts) >= 2:
                        try:
                            crash_file = Path(parts[0])
                            crash_line = int(parts[1])
                            
                            crash_info = {
                                "type": "reference_crash_target_runs",
                                "scenario": "ref_crashes_target_runs_different_paths",
                                "ref_crash_type": ref_crash_type,
                                "ref_crash_function": crash_function,
                                "ref_stack": [frame['raw_line'] for frame in ref_stack],
                                "crash_location": {
                                    "file": str(crash_file),  # convert to string
                                    "line": crash_line,
                                    "function": crash_function.get('function', 'unknown')
                                },
                                "target_crashed": target_crashed,
                                "difference": f"ref_crashes_at_{crash_function['function']}_{crash_function['file_line']}_target_runs_normally",
                                "analysis": f"the reference version crashes in function {crash_function['function']} , the target version did not crash, so the input file must be modified to make the target version crash as well"
                            }
                            self.fork_point = crash_info
                            print(f"✅ found the reference version crash point: {crash_function['function']} at {crash_function['file_line']}")
                            
                            # try to find the user code location from the raw stack information
                            user_crash_info = self.find_user_crash_location(ref_stack)
                            if user_crash_info:
                                print(f"found the user code crash point: {user_crash_info}")
                                crash_info["user_crash_location"] = user_crash_info
                            
                            # also run the input modification analysis for this case
                            print("Start analyzing the input file modification strategy...")
                            crash_analysis = {
                                "line_number": crash_line,
                                "file_path": str(crash_file),
                                "code_snippet": "",  # obtain from the source code
                                "potential_causes": ["unknown"],
                                "analysis": {"type": "unknown"}
                            }
                            
                            # try to obtain the crash line code
                            try:
                                with open(crash_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    lines = f.readlines()
                                    if 0 <= crash_line - 1 < len(lines):
                                        crash_analysis["code_snippet"] = lines[crash_line - 1].strip()
                            except:
                                pass
                            
                            related_vars = self.extract_related_vars_from_stack(ref_stack)
                            print(f"crash-point-related variables: {related_vars}")
                            
                            # create the input modification analyzer
                            input_modifier = InputModifierAnalyzer(
                                str(self.target_build_dir),
                                str(self.input_file),
                                related_vars,
                                crash_analysis,
                                self.execution_config,
                                ref_crash_type  # pass the actual crash type of the reference version
                            )
                            
                            # run the input modification analysis
                            modification_results = input_modifier.run_analysis()
                            
                            # add the modification results to the fork point information
                            crash_info["input_modification_analysis"] = modification_results
                            
                            return crash_info
                        except ValueError:
                            print(f"unable to parse the crash location: {crash_location}")
            else:
                print("the reference version crashed but there is no usable stack information")
                crash_info = {
                    "type": "reference_crash_no_stack_info",
                    "scenario": "ref_crashes_no_stack_info_target_runs",
                    "ref_crash_type": ref_crash_type,
                    "ref_stderr_sample": ref_stderr[:500],
                    "target_crashed": target_crashed,
                    "difference": "ref_crashes_but_no_stack_trace_available"
                }
                self.fork_point = crash_info
                return crash_info
        
        # Case 2: both versions crash
        elif ref_crashed and target_crashed:
            print("both versions crash, check the crash type and location")
            
            # extract the crash type
            ref_crash_type = self.extract_crash_type(ref_stderr)
            target_crash_type = self.extract_crash_type(target_stderr)
            
            print(f"reference version crash type: {ref_crash_type}")
            print(f"target version crashedtype: {target_crash_type}")
            
            # extract the detailed crash location (stack trace)
            ref_stack = self.extract_detailed_stack_trace(ref_stderr)
            target_stack = self.extract_detailed_stack_trace(target_stderr)
            
            # compare the crash types
            if ref_crash_type != target_crash_type:
                # find the first crash-related function in the target version (the function closest to the crash point)
                target_crash_function = None
                for frame in target_stack:
                    if any(keyword in frame['function'].lower() for keyword in ['wave', 'read', 'open', 'init', 'img', 'decode', 'tiff', 'crop']):
                        target_crash_function = frame
                        break
                
                fork_info = {
                    "type": "crash_type_difference",
                    "scenario": "both_crash_different",
                    "ref_crash_type": ref_crash_type,
                    "target_crash_type": target_crash_type,
                    "ref_stack": [frame['raw_line'] for frame in ref_stack],
                    "target_stack": [frame['raw_line'] for frame in target_stack],
                    "target_crash_function": target_crash_function,
                    "difference": f"different_crash_type, target_crash_at_{target_crash_function['function']}_{target_crash_function['file_line']}" if target_crash_function else "different_crash_type"
                }
                self.fork_point = fork_info
                print(f"fork found at the crash point: crash type difference {ref_crash_type} vs {target_crash_type}")
                if target_crash_function:
                    print(f"the target version crashed at: {target_crash_function['function']} at {target_crash_function['file_line']}")
                    
                    # also run the input modification analysis for this case
                    print("Start analyzing the input file modification strategy...")
                    crash_analysis = {
                        "line_number": target_crash_function['file_line'].rsplit(':', 1)[1] if ':' in target_crash_function['file_line'] else 0,
                        "file_path": target_crash_function['file_line'].rsplit(':', 1)[0] if ':' in target_crash_function['file_line'] else "unknown",
                        "code_snippet": f"Function: {target_crash_function['function']}",
                        "potential_causes": ["function_call"],
                        "analysis": {"type": "function_call", "function": target_crash_function['function']}
                    }
                    
                    related_vars = [target_crash_function['function']]
                    print(f"crash-point-related variables: {related_vars}")
                    
                    # create the input modification analyzer
                    input_modifier = InputModifierAnalyzer(
                        str(self.target_build_dir),
                        str(self.input_file),
                        related_vars,
                        crash_analysis,
                        self.execution_config,
                        ref_crash_type  # pass the actual crash type of the reference version
                    )
                    
                    # run the input modification analysis
                    modification_results = input_modifier.run_analysis()
                    
                    # add the modification results to the fork point information
                    fork_info["input_modification_analysis"] = modification_results
                    
                return fork_info
            
            # compare the crash locations (stack trace)
            if ref_stack != target_stack:
                # find the nearest fork point (search backward from the top of the stack)
                min_len = min(len(ref_stack), len(target_stack))
                fork_frame = -1
                
                for i in range(min_len):
                    if ref_stack[i]['function'] != target_stack[i]['function'] or \
                       ref_stack[i]['file_line'] != target_stack[i]['file_line']:
                        fork_frame = i
                        break
                
                if fork_frame != -1:
                    # find the user code function closest to the crash point (excluding system functions)
                    user_frame = None
                    for i in range(len(target_stack)):
                        frame = target_stack[i]
                        # check whether it is user code (contains a version path)
                        if '/versions/' in frame['file_line'] or '/src/' in frame['file_line']:
                            # check whether it is a memory allocation function; if so, find the function that calls it
                            frame_func = frame['function']
                            is_memory_func = any(mem_func in frame_func for mem_func in self.memory_allocation_functions)
                            
                            if not is_memory_func:
                                user_frame = frame
                                break
                        elif i == len(target_stack) - 1 and user_frame is None:  # if no non-memory-allocation function is found after the whole traversal, use the last one
                            # check whether the last frame is a memory allocation function
                            frame_func = frame['function']
                            is_memory_func = any(mem_func in frame_func for mem_func in self.memory_allocation_functions)
                            
                            if not is_memory_func:
                                user_frame = frame
                            else:
                                # if the last one is a memory allocation function, try to find the previous non-memory-allocation function
                                for j in range(len(target_stack) - 1, -1, -1):
                                    prev_frame = target_stack[j]
                                    prev_func = prev_frame['function']
                                    is_prev_memory_func = any(mem_func in prev_func for mem_func in self.memory_allocation_functions)
                                    
                                    if not is_prev_memory_func:
                                        user_frame = prev_frame
                                        break
                                
                                if user_frame is None:
                                    user_frame = frame  # if there really is no non-memory-allocation function, use the last memory allocation function
    
                    if user_frame:
                        fork_info = {
                            "type": "execution_path_difference",
                            "scenario": "both_crash_different_paths",
                            "fork_frame": fork_frame,
                            "ref_stack": [frame['raw_line'] for frame in ref_stack],
                            "target_stack": [frame['raw_line'] for frame in target_stack],
                            "ref_fork_function": ref_stack[fork_frame]['function'] if fork_frame < len(ref_stack) else "unknown",
                            "target_fork_function": target_stack[fork_frame]['function'] if fork_frame < len(target_stack) else "unknown",
                            "target_crash_function": user_frame,
                            "difference": f"execution path differs at frame {fork_frame}, target_crash_at_{user_frame['function']}_{user_frame['file_line']}"
                        }
                        self.fork_point = fork_info
                        print(f"fork found at stack frame {fork_frame} near the crash point: {ref_stack[fork_frame]['function']} vs {target_stack[fork_frame]['function']}")
                        print(f"the target version crashed at: {user_frame['function']} at {user_frame['file_line']}")
                        
                        # also run the input modification analysis for this case
                        print("Start analyzing the input file modification strategy...")
                        crash_analysis = {
                            "line_number": user_frame['file_line'].rsplit(':', 1)[1] if ':' in user_frame['file_line'] else 0,
                            "file_path": user_frame['file_line'].rsplit(':', 1)[0] if ':' in user_frame['file_line'] else "unknown",
                            "code_snippet": f"Function: {user_frame['function']}",
                            "potential_causes": ["function_call"],
                            "analysis": {"type": "function_call", "function": user_frame['function']}
                        }
                        
                        related_vars = [user_frame['function']]
                        print(f"crash-point-related variables: {related_vars}")
                        
                        # create the input modification analyzer
                        input_modifier = InputModifierAnalyzer(
                            str(self.target_build_dir),
                            str(self.input_file),
                            related_vars,
                            crash_analysis,
                            self.execution_config,
                            ref_crash_type  # pass the actual crash type of the reference version
                        )
                        
                        # run the input modification analysis
                        modification_results = input_modifier.run_analysis()
                        
                        # add the modification results to the fork point information
                        fork_info["input_modification_analysis"] = modification_results
                        
                        return fork_info
                    else:
                        fork_info = {
                            "type": "execution_path_difference",
                            "scenario": "both_crash_different_paths",
                            "fork_frame": fork_frame,
                            "ref_stack": [frame['raw_line'] for frame in ref_stack],
                            "target_stack": [frame['raw_line'] for frame in target_stack],
                            "ref_fork_function": ref_stack[fork_frame]['function'] if fork_frame < len(ref_stack) else "unknown",
                            "target_fork_function": target_stack[fork_frame]['function'] if fork_frame < len(target_stack) else "unknown",
                            "difference": f"execution path differs at frame {fork_frame}"
                        }
                        self.fork_point = fork_info
                        print(f"fork found at stack frame {fork_frame} near the crash point: {ref_stack[fork_frame]['function']} vs {target_stack[fork_frame]['function']}")
                        
                        # also run the input modification analysis for this case
                        print("Start analyzing the input file modification strategy...")
                        crash_analysis = {
                            "line_number": 0,
                            "file_path": "unknown",
                            "code_snippet": f"Function: {target_stack[fork_frame]['function'] if fork_frame < len(target_stack) else 'unknown'}",
                            "potential_causes": ["function_call"],
                            "analysis": {"type": "function_call", "function": target_stack[fork_frame]['function'] if fork_frame < len(target_stack) else "unknown"}
                        }
                        
                        related_vars = [target_stack[fork_frame]['function']] if fork_frame < len(target_stack) else []
                        print(f"crash-point-related variables: {related_vars}")
                        
                        # create the input modification analyzer
                        input_modifier = InputModifierAnalyzer(
                            str(self.target_build_dir),
                            str(self.input_file),
                            related_vars,
                            crash_analysis,
                            self.execution_config,
                            ref_crash_type  # pass the actual crash type of the reference version
                        )
                        
                        # run the input modification analysis
                        modification_results = input_modifier.run_analysis()
                        
                        # add the modification results to the fork point information
                        fork_info["input_modification_analysis"] = modification_results
                        
                        return fork_info
        
        # Case 3: reference version does not crash, target version crashes (less common)
        elif not ref_crashed and target_crashed:
            print("reference version runs normally, target version crashes - the old version has a vulnerability")
            
            target_crash_type = self.extract_crash_type(target_stderr)
            target_stack = self.extract_detailed_stack_trace(target_stderr)
            
            if target_stack:
                # filter the user code stack
                user_stack = self.filter_user_code_stack(target_stack)
                
                if user_stack:
                    # check whether it crashed inside a memory allocation function; if so, find the location that calls that function
                    memory_frames = self.find_memory_allocation_frames(user_stack)
                    
                    if memory_frames:
                        # find the non-memory-allocation function call closest to the crash point
                        crash_function = None
                        for frame in user_stack:
                            frame_func = frame['function']
                            is_memory_func = any(mem_func in frame_func for mem_func in self.memory_allocation_functions)
                            
                            if not is_memory_func:
                                crash_function = frame
                                break
                        
                        if crash_function is None:
                            # if all frames are memory allocation functions, use the first non-memory-allocation function (if there is none, use the last one)
                            crash_function = user_stack[-1]
                    else:
                        # no memory allocation function, directly use the first user code function
                        crash_function = user_stack[0]
                    
                    fork_info = {
                        "type": "vulnerability_in_older_version",
                        "scenario": "ref_runs_target_crashes",
                        "target_crash_type": target_crash_type,
                        "target_crash_function": crash_function,
                        "target_stack": [frame['raw_line'] for frame in target_stack],
                        "target_user_stack": [frame['raw_line'] for frame in user_stack],
                        "ref_crashed": ref_crashed,
                        "difference": f"vulnerability_in_older_version_at_{crash_function['function']}_{crash_function['file_line']}",
                        "analysis": f"the target version (old version) has a vulnerability in function {crash_function['function']} ",
                        "memory_allocation_context": memory_frames  # add the memory allocation context information
                    }
                    self.fork_point = fork_info
                    print(f"found an old version vulnerability: {crash_function['function']} at {crash_function['file_line']}")
                    
                    # also run the input modification analysis for this case
                    print("Start analyzing the input file modification strategy...")
                    crash_analysis = {
                        "line_number": crash_function['file_line'].rsplit(':', 1)[1] if ':' in crash_function['file_line'] else 0,
                        "file_path": crash_function['file_line'].rsplit(':', 1)[0] if ':' in crash_function['file_line'] else "unknown",
                        "code_snippet": f"Function: {crash_function['function']}",
                        "potential_causes": ["function_call"],
                        "analysis": {"type": "function_call", "function": crash_function['function']}
                    }
                    
                    related_vars = [crash_function['function']]
                    print(f"crash-point-related variables: {related_vars}")
                    
                    # create the input modification analyzer
                    input_modifier = InputModifierAnalyzer(
                        str(self.target_build_dir),
                        str(self.input_file),
                        related_vars,
                        crash_analysis,
                        self.execution_config,
                        ref_crash_type  # pass the actual crash type of the reference version
                    )
                    
                    # run the input modification analysis
                    modification_results = input_modifier.run_analysis()
                    
                    # add the modification results to the fork point information
                    fork_info["input_modification_analysis"] = modification_results
                    
                    return fork_info
                else:
                    # no user code filtered out, using the raw stack
                    crash_function = target_stack[0]
                    fork_info = {
                        "type": "vulnerability_in_older_version",
                        "scenario": "ref_runs_target_crashes",
                        "target_crash_type": target_crash_type,
                        "target_crash_function": crash_function,
                        "target_stack": [frame['raw_line'] for frame in target_stack],
                        "ref_crashed": ref_crashed,
                        "difference": f"vulnerability_in_older_version_at_{crash_function['function']}_{crash_function['file_line']}",
                        "analysis": f"the target version (old version) has a vulnerability in function {crash_function['function']} "
                    }
                    self.fork_point = fork_info
                    print(f"found an old version vulnerability: {crash_function['function']} at {crash_function['file_line']}")
                    
                    # also run the input modification analysis for this case
                    print("Start analyzing the input file modification strategy...")
                    crash_analysis = {
                        "line_number": crash_function['file_line'].rsplit(':', 1)[1] if ':' in crash_function['file_line'] else 0,
                        "file_path": crash_function['file_line'].rsplit(':', 1)[0] if ':' in crash_function['file_line'] else "unknown",
                        "code_snippet": f"Function: {crash_function['function']}",
                        "potential_causes": ["function_call"],
                        "analysis": {"type": "function_call", "function": crash_function['function']}
                    }
                    
                    related_vars = [crash_function['function']]
                    print(f"crash-point-related variables: {related_vars}")
                    
                    # create the input modification analyzer
                    input_modifier = InputModifierAnalyzer(
                        str(self.target_build_dir),
                        str(self.input_file),
                        related_vars,
                        crash_analysis,
                        self.execution_config,
                        ref_crash_type  # pass the actual crash type of the reference version
                    )
                    
                    # run the input modification analysis
                    modification_results = input_modifier.run_analysis()
                    
                    # add the modification results to the fork point information
                    fork_info["input_modification_analysis"] = modification_results
                    
                    return fork_info
            else:
                fork_info = {
                    "type": "vulnerability_in_older_version",
                    "scenario": "ref_runs_target_crashes",
                    "target_crash_type": target_crash_type,
                    "target_stderr": target_stderr[:500],  # first 500 characters
                    "ref_crashed": ref_crashed,
                    "difference": "vulnerability_in_older_version"
                }
                self.fork_point = fork_info
                print(f"found an old version vulnerability: the target version crashes but the reference version is normal")
                return fork_info
        
        # Case 4: neither version crashes, but the behavior differs
        else:
            print("neither version crashes, compare the output and behavior differences")
            
            ref_stdout = self.ref_trace.get("stdout", "")
            target_stdout = self.target_trace.get("stdout", "")
            
            # compare the difference in the error output
            ref_stderr_short = self.ref_trace.get("stderr", "")
            target_stderr_short = self.target_trace.get("stderr", "")
            
            # special handling: even if the return code is 0, different error output may still indicate a behavior difference
            if ref_stderr_short != target_stderr_short:
                # check whether there is a substantive difference (ignore warning messages)
                ref_warnings_filtered = self._filter_warnings(ref_stderr_short)
                target_warnings_filtered = self._filter_warnings(target_stderr_short)
                
                if ref_warnings_filtered != target_warnings_filtered:
                    fork_info = {
                        "type": "behavior_difference",
                        "scenario": "both_run_different_error_output",
                        "ref_stderr_length": len(ref_stderr_short),
                        "target_stderr_length": len(target_stderr_short),
                        "ref_filtered_stderr": ref_warnings_filtered[:500],
                        "target_filtered_stderr": target_warnings_filtered[:500],
                        "difference": "different_error_output_behavior"
                    }
                    self.fork_point = fork_info
                    print("found behavior difference: error output differs")
                    return fork_info
            
            if ref_stdout != target_stdout:
                fork_info = {
                    "type": "behavior_difference",
                    "scenario": "both_run_different_output",
                    "ref_stdout_length": len(ref_stdout),
                    "target_stdout_length": len(target_stdout),
                    "difference": "different_output_behavior"
                }
                self.fork_point = fork_info
                print("found behavior difference: output differs")
                return fork_info
            else:
                print("both versions behave the same, no fork point")
                return None

    def filter_user_code_stack(self, stack_trace: List[Dict]) -> List[Dict]:
        """filter the stack trace, keeping only user code (exclude sanitizer, system libraries, etc.)"""
        user_stack = []
        
        for frame in stack_trace:
            file_line = frame['file_line']
            function = frame['function']
            
            # exclude sanitizer internal code
            if any(keyword in file_line.lower() for keyword in ['sanitizer', 'interceptor', '__interceptor']):
                continue
            
            # exclude system library functions
            if any(keyword in function.lower() for keyword in ['__libc_', '__GI_', '_start', 'main']):
                continue
            
            # exclude standard library functions
            if any(lib in file_line for lib in ['/lib/', '/usr/lib/', '/lib64/', '/usr/lib64/']):
                continue
            
            # keep user code
            user_stack.append(frame)
        
        return user_stack

    def find_user_crash_location(self, stack_trace: List[Dict]) -> Optional[Dict]:
        """find the user code crash location from the stack trace"""
        user_stack = self.filter_user_code_stack(stack_trace)
        
        if user_stack:
            # return the first user code crash location
            crash_frame = user_stack[0]
            file_line = crash_frame['file_line']
            
            # parse the file and line number
            parts = file_line.rsplit(':', 1)
            if len(parts) >= 2:
                try:
                    crash_file = Path(parts[0])
                    crash_line = int(parts[1])
                    
                    return {
                        "file": str(crash_file),
                        "line": crash_line,
                        "function": crash_frame['function']
                    }
                except ValueError:
                    pass
        
        return None

    def extract_related_vars_from_stack(self, stack_trace: List[Dict]) -> List[str]:
        """extract related variables from the stack trace"""
        related_vars = set()
        
        for frame in stack_trace:
            function = frame['function']
            # extract variable names from the function name
            var_matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', function)
            for var in var_matches:
                if var not in ['if', 'while', 'for', 'return', 'int', 'char', 'void', 'const', 'struct', 'class', 'static']:
                    related_vars.add(var)
        
        return list(related_vars)

    def _filter_warnings(self, stderr: str) -> str:
        """filter out common warning messages, keeping only the important error messages"""
        lines = stderr.split('\n')
        filtered_lines = []
        
        warning_patterns = [
            r'warning:',
            r'trailing garbage in marker segment',
            r'ignoring invalid option',
            r'ignoring unknown marker segment',
            r'warning: ignoring invalid option',
            r'warning: trailing garbage',
            r'warning: ignoring unknown marker',
            r'TIFFReadDirectoryCheckOrder:',
            r'TIFFReadDirectory:',
            r'TIFFFetchNormalTag:',
            r'TIFFAdvanceDirectory:',
            r'loadImage:',
            r'Fax4Decode:',
            r'_TIFFVSetField:',
            r'TIFFFetchStripThing:',
            r'Sanity check on size of',
            r'Bad value \d+ for',
            r'ASCII value for tag',
            r'IO error during reading of',
            r'Incorrect count for',
            r'Bogus',
            r'Premature EOL',
            r'Bad code word',
            r'Line length mismatch',
            r'Invalid TIFF directory',
            r'Unknown field with tag',
            r'Ignoring ColorMap',
            r'Image lacks Photometric',
            r'Error fetching directory count',
            r'AddressSanitizer: WARNING:'
        ]
        
        for line in lines:
            is_warning = False
            for pattern in warning_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    is_warning = True
                    break
            if not is_warning:
                filtered_lines.append(line)
        
        return '\n'.join(filtered_lines)

    def analyze_fork_point(self) -> Dict:
        """analyze the fork point"""
        if not self.fork_point:
            return {}
        
        print("Analyzing fork point...")
        
        analysis_result = {
            "type": "comprehensive_analysis",
            "fork_point_info": self.fork_point,
            "description": f"fork point type: {self.fork_point['type']}, scenario: {self.fork_point['scenario']}"
        }
        
        # provide detailed analysis according to different scenarios
        scenario = self.fork_point.get('scenario', '')
        
        if scenario == 'ref_crashes_target_runs_different_paths':
            # reference version crashes, target version (old version) normal - path fork
            if 'ref_crash_function' in self.fork_point:
                crash_func = self.fork_point['ref_crash_function']
                analysis_result['detailed_analysis'] = {
                    "vulnerability_location": f"{crash_func['function']} at {crash_func['file_line']}",
                    "status": "vulnerability_exists_but_not_reached_in_older_version",
                    "explanation": "the reference version reached the vulnerable code and crashed, but the target version (old version) did not reach the vulnerable code due to different input handling or execution path",
                    "recommendation": f"analyze {crash_func['file_line']} the vulnerable code, and compare the execution path differences between the two versions"
                }
            elif 'ref_fork_function' in self.fork_point:
                # fork point found using path analysis
                analysis_result['detailed_analysis'] = {
                    "fork_point_location": f"function {self.fork_point['ref_fork_function']} vs {self.fork_point['target_fork_function']}",
                    "fork_point_index": self.fork_point['fork_index'],
                    "status": "execution_path_divergence_before_vulnerability",
                    "explanation": f"the two versions fork paths when executing the {self.fork_point['fork_index']} -th function, and the target version did not reach the vulnerable code",
                    "recommendation": f"analyze the implementation differences between functions {self.fork_point['ref_fork_function']} / {self.fork_point['target_fork_function']} "
                }
        
        elif scenario == 'both_crash_different':
            # both versions crash, but with different types
            if 'target_crash_function' in self.fork_point:
                crash_func = self.fork_point['target_crash_function']
                analysis_result['detailed_analysis'] = {
                    "crash_location": f"{crash_func['function']} at {crash_func['file_line']}",
                    "status": "different_vulnerability",
                    "recommendation": f"analyze {crash_func['file_line']} the code, the two versions have different types of vulnerabilities"
                }
        
        elif scenario == 'ref_runs_target_crashes':
            # reference version normal, target version crashes - the old version has a vulnerability
            if 'target_crash_function' in self.fork_point:
                crash_func = self.fork_point['target_crash_function']
                analysis_result['detailed_analysis'] = {
                    "vulnerability_location": f"{crash_func['function']} at {crash_func['file_line']}",
                    "status": "vulnerability_in_older_version",
                    "recommendation": f"analyze {crash_func['file_line']} the code, the target version (old version) has this vulnerability"
                }
        
        print(f"fork point analysis result: {analysis_result['type']}")
        print(f"detailed analysis: {analysis_result.get('detailed_analysis', 'N/A')}")
        return analysis_result

    def run_analysis(self):
        """run the full vulnerability migration analysis"""
        print("Start vulnerability migration analysis (full version)...")
        self.start_timer()
        
        try:
            # 1. obtain the execution traces of the two versions
            ref_crashed, target_crashed = self.record_execution_traces()
            
            # 2. compare the execution traces of the two versions to find the fork point
            print("Start trace comparison...")
            self.trace_comparison_start_time = time.time()
            fork_point = self.find_fork_point()
            self.trace_comparison_time = time.time() - self.trace_comparison_start_time
            
            if not fork_point:
                print("no fork point found")
                self.stop_timer()
                return None
            else:
                print(f"found fork point: {fork_point}")

                # attach v2 function-level/statement-level alignment results
                if getattr(self, 'v2_alignment_results', None):
                    fork_point['v2_alignment'] = self.v2_alignment_results
                    if self.v2_alignment_results.get('key_fork_point'):
                        self.key_fork_point = self.v2_alignment_results['key_fork_point']
                    try:
                        with open(self.results_dir / "function_alignment.json", 'w') as f:
                            json.dump(self.v2_alignment_results, f, indent=2, ensure_ascii=False)
                        print("function-level alignment and statement-level alignment results have been saved to function_alignment.json")
                    except Exception:
                        pass

                # 3. analyze the fork point
                print("Run fork point analysis...")
                self.fork_point_analysis_start_time = time.time()
                analysis = self.analyze_fork_point()
                self.fork_point_analysis_time = time.time() - self.fork_point_analysis_start_time
                print(f"fork point analysis result: {analysis}")
            
            # save fork point information to a file for subsequent traceability analysis
            fork_point_file = self.results_dir / "fork_point.json"
            with open(fork_point_file, 'w') as f:
                json.dump({
                    "fork_point": fork_point,
                    "analysis": analysis
                }, f, indent=2)
            
            print(f"fork point information saved to: {fork_point_file}")
            
            # 4. if a fork point is found, automatically start traceability analysis
            target_crash_function = None
            
            # prefer the user code crash function, otherwise use the raw crash function
            if fork_point and 'user_crash_location' in fork_point:
                crash_location = fork_point['user_crash_location']
                target_crash_function = {
                    "file_line": f"{crash_location['file']}:{crash_location['line']}",
                    "function": crash_location['function']
                }
            elif fork_point and 'crash_location' in fork_point:
                crash_location = fork_point['crash_location']
                target_crash_function = {
                    "file_line": f"{crash_location['file']}:{crash_location['line']}",
                    "function": crash_location.get('function', 'unknown')
                }
            elif fork_point and 'target_crash_function' in fork_point:
                target_crash_function = fork_point['target_crash_function']
                crash_location_str = target_crash_function['file_line']
                
                # parse the crash location
                parts = crash_location_str.rsplit(':', 1)
                if len(parts) >= 2:
                    try:
                        crash_file = Path(parts[0])
                        crash_line = int(parts[1])
                        crash_location = {
                            "file": str(crash_file),
                            "line": crash_line,
                            "function": target_crash_function.get('function', 'unknown')
                        }
                    except ValueError:
                        print(f"unable to parse the crash location: {crash_location_str}")
                        crash_location = None
                else:
                    crash_location = None
            else:
                crash_location = None
            
            if crash_location and target_crash_function:
                print(f"\nStart automatic traceability analysis...")
                print(f"crash location: {crash_location}")
                
                # create the traceability analyzer, passing in the build directories
                tracer_analyzer = UniversalTracerAnalyzer(
                    str(self.reference_version_path),
                    str(self.target_version_path), 
                    str(self.input_file),
                    crash_location,
                    str(self.target_build_dir),  # new parameter
                    str(self.ref_build_dir),      # new parameter
                    self.execution_config         # new parameter
                )
                
                # run the traceability analysis
                self.tracer_analysis_start_time = time.time()
                trace_result = tracer_analyzer.run_analysis()
                self.tracer_analysis_time = time.time() - self.tracer_analysis_start_time
                
                # merge the results
                final_result = {
                    "fork_point_analysis": analysis,
                    "trace_analysis": trace_result,
                    "combined_insights": self.combine_analyses(analysis, trace_result)
                }
                # inject v2 key fork-point positions
                kf = getattr(self, 'key_fork_point', None)
                if kf:
                    final_result["fork_point_location"] = kf.get("summary", "")
                    final_result["key_fork_point"] = kf
                
                # save the final results
                final_result_file = self.results_dir / "final_analysis.json"
                with open(final_result_file, 'w') as f:
                    json.dump(final_result, f, indent=2)
                
                print(f"final analysis results saved to: {final_result_file}")
                
                # 5. run fork-point triggering offset position analysis and match detection
                print(f"\nStart fork-point triggering offset position analysis and match detection...")
                
                # first find the target version executable
                target_program = self.find_executable(self.target_build_dir / "tools", "target")
                if not target_program:
                    target_program = self.find_executable(self.target_build_dir, "target")
                
                if target_program:
                    print(f"Using target program: {target_program}")
                    
                    # record the time from the end of compilation to the start of the triggering analysis
                    trigger_analysis_start_time = time.time()
                    
                    # get the reference version crash type for match detection
                    ref_crash_type = self.extract_crash_type(self.ref_trace.get("stderr", ""))
                    ref_stack_trace = self.extract_detailed_stack_trace(self.ref_trace.get("stderr", ""))
                    
                    # use the InputModifierAnalyzer analysis results instead of re-analyzing
                    input_modification_results = fork_point.get("input_modification_analysis", {})
                    triggering_offsets = self.extract_triggering_offsets_from_input_modification(input_modification_results)
                    
                    # create match detection results
                    matching_results = self.create_matching_results(triggering_offsets, ref_crash_type)
                    
                    # integrate the results
                    trigger_result = {
                        "original_input_result": {"crashed": False, "crash_type": "no_crash"},  # assume the original input did not crash
                        "single_triggering_offsets": [item for item in triggering_offsets if 'offset' in item],  # single offset
                        "double_triggering_offsets": [item for item in triggering_offsets if 'offset1' in item],  # double offset
                        "triple_triggering_offsets": [item for item in triggering_offsets if 'offset1' in item and 'offset3' in item],  # triple offset
                        "quadruple_triggering_offsets": [item for item in triggering_offsets if 'offset1' in item and 'offset4' in item],  # quadruple offset
                        "quintuple_triggering_offsets": [item for item in triggering_offsets if 'offset1' in item and 'offset5' in item],  # quintuple offset
                        "all_triggering_offsets": triggering_offsets,
                        "matching_results": matching_results,
                        "best_match": self.find_best_match(matching_results),
                        "summary": {
                            "total_single_triggering_offsets": len([item for item in triggering_offsets if 'offset' in item]),
                            "total_double_triggering_offsets": len([item for item in triggering_offsets if 'offset1' in item]),
                            "total_triple_triggering_offsets": len([item for item in triggering_offsets if 'offset1' in item and 'offset3' in item]),
                            "total_quadruple_triggering_offsets": len([item for item in triggering_offsets if 'offset1' in item and 'offset4' in item]),
                            "total_quintuple_triggering_offsets": len([item for item in triggering_offsets if 'offset1' in item and 'offset5' in item]),
                            "total_all_triggering_offsets": len(triggering_offsets),
                            "total_matching_results": len(matching_results),
                            "matching_details": [info["description"] for info in matching_results if info["is_match"]],
                            "non_matching_details": [info["description"] for info in matching_results if not info["is_match"]],
                            "ref_crash_type": ref_crash_type
                        },
                        "recommendations": self.generate_recommendations(triggering_offsets, matching_results)
                    }
                    
                    # merge the triggering analysis results
                    final_result["fork_point_trigger_analysis"] = trigger_result
                    
                    # update the final results file
                    with open(final_result_file, 'w') as f:
                        json.dump(final_result, f, indent=2)
                    
                    print(f"updated final analysis results with fork-point triggering offset position analysis and match detection")
                else:
                    print("Warning: target version executable not found, skipping fork-point triggering analysis")
                
                # 6. run rr reverse debugging analysis
                print(f"\nStart rr reverse debugging analysis...")
                
                # get related variables for rr analysis
                related_vars = []
                if trace_result:
                    related_vars = trace_result.get("variable_analysis", {}).get("related_variables", [])
                
                if not related_vars and input_modification_results:
                    related_vars = input_modification_results.get("related_variables", [])
                
                if related_vars and target_program:
                    print(f"perform rr reverse analysis on the following variables: {related_vars}")
                    
                    # create the RR reverse analyzer
                    rr_analyzer = RRBackwardAnalysis(
                        str(target_program),
                        str(self.input_file),
                        crash_location
                    )
                    
                    # run the rr analysis
                    rr_analysis_result = rr_analyzer.run_analysis(related_vars)
                    
                    # add the rr analysis results to the final results
                    final_result["rr_backward_analysis"] = rr_analysis_result
                    
                    # update the final results file
                    with open(final_result_file, 'w') as f:
                        json.dump(final_result, f, indent=2)
                    
                    print(f"updated final analysis results with rr reverse debugging analysis")
                else:
                    print(f"skipping rr reverse analysis (related variables: {len(related_vars)}, executable: {bool(target_program)})")
                
                # 7. save important results to a specified file
                self.save_important_results(final_result)
                
                self.stop_timer()
                return final_result_file
            else:
                print("no crash function available for traceability analysis")
                self.stop_timer()
                return fork_point_file
            
        except Exception as e:
            print(f"an error occurred during analysis: {e}")
            import traceback
            traceback.print_exc()
            self.stop_timer()
            return None
        finally:
            # note: do not clean up the working directory here, because the results need to be saved for traceability analysis
            print(f"analysis results saved in: {self.results_dir}")

    def extract_triggering_offsets_from_input_modification(self, input_modification_results: Dict) -> List[Dict]:
        """
        extract triggering offset positions from the InputModifierAnalyzer results
        """
        triggering_offsets = []
        
        # extract from the format-aware results
        format_aware_results = input_modification_results.get("format_aware_results", {})
        format_aware_triggering_modifications = format_aware_results.get("format_aware_triggering_modifications", [])
        
        for mod in format_aware_triggering_modifications:
            triggering_offsets.append({
                "offset": mod.get("offset"),
                "field_name": mod.get("field_name"),
                "original_value": mod.get("original_value"),
                "new_value": mod.get("new_value"),
                "crash_type": mod.get("crash_type"),
                "crash_reason": mod.get("crash_reason"),
                "description": mod.get("description"),
                "found_time": mod.get("found_time", "N/A")  # add the discovery time
            })
        
        # extract from the single-offset results
        single_results = input_modification_results.get("single_offset_results", {})
        triggering_modifications = single_results.get("triggering_modifications", [])
        
        for mod in triggering_modifications:
            triggering_offsets.append({
                "offset": mod.get("offset"),
                "original_value": mod.get("original_value"),
                "new_value": mod.get("new_value"),
                "crash_type": mod.get("crash_type"),
                "crash_reason": mod.get("crash_reason"),
                "description": mod.get("description"),
                "found_time": mod.get("found_time", "N/A")  # add the discovery time
            })
        
        # extract from the double-offset results
        double_results = input_modification_results.get("double_offset_results", {})
        double_triggering_modifications = double_results.get("double_offset_triggering_modifications", [])
        
        for mod in double_triggering_modifications:
            triggering_offsets.append({
                "offset1": mod.get("offset1"),
                "offset2": mod.get("offset2"),
                "original_value1": mod.get("original_value1"),
                "original_value2": mod.get("original_value2"),
                "new_value1": mod.get("new_value1"),
                "new_value2": mod.get("new_value2"),
                "crash_type": mod.get("crash_type"),
                "crash_reason": mod.get("crash_reason"),
                "description": mod.get("description"),
                "found_time": mod.get("found_time", "N/A")  # add the discovery time
            })
        
        # extract from the triple-offset results
        triple_results = input_modification_results.get("triple_offset_results", {})
        triple_triggering_modifications = triple_results.get("triple_offset_triggering_modifications", [])
        
        for mod in triple_triggering_modifications:
            triggering_offsets.append({
                "offset1": mod.get("offset1"),
                "offset2": mod.get("offset2"),
                "offset3": mod.get("offset3"),
                "original_value1": mod.get("original_value1"),
                "original_value2": mod.get("original_value2"),
                "original_value3": mod.get("original_value3"),
                "new_value1": mod.get("new_value1"),
                "new_value2": mod.get("new_value2"),
                "new_value3": mod.get("new_value3"),
                "crash_type": mod.get("crash_type"),
                "crash_reason": mod.get("crash_reason"),
                "description": mod.get("description"),
                "found_time": mod.get("found_time", "N/A")  # add the discovery time
            })
        
        # extract from the quadruple-offset results
        quadruple_results = input_modification_results.get("quadruple_offset_results", {})
        quadruple_triggering_modifications = quadruple_results.get("quadruple_offset_triggering_modifications", [])
        
        for mod in quadruple_triggering_modifications:
            triggering_offsets.append({
                "offset1": mod.get("offset1"),
                "offset2": mod.get("offset2"),
                "offset3": mod.get("offset3"),
                "offset4": mod.get("offset4"),
                "original_value1": mod.get("original_value1"),
                "original_value2": mod.get("original_value2"),
                "original_value3": mod.get("original_value3"),
                "original_value4": mod.get("original_value4"),
                "new_value1": mod.get("new_value1"),
                "new_value2": mod.get("new_value2"),
                "new_value3": mod.get("new_value3"),
                "new_value4": mod.get("new_value4"),
                "crash_type": mod.get("crash_type"),
                "crash_reason": mod.get("crash_reason"),
                "description": mod.get("description"),
                "found_time": mod.get("found_time", "N/A")  # add the discovery time
            })
        
        # extract from the quintuple-offset results
        quintuple_results = input_modification_results.get("quintuple_offset_results", {})
        quintuple_triggering_modifications = quintuple_results.get("quintuple_offset_triggering_modifications", [])
        
        for mod in quintuple_triggering_modifications:
            triggering_offsets.append({
                "offset1": mod.get("offset1"),
                "offset2": mod.get("offset2"),
                "offset3": mod.get("offset3"),
                "offset4": mod.get("offset4"),
                "offset5": mod.get("offset5"),
                "original_value1": mod.get("original_value1"),
                "original_value2": mod.get("original_value2"),
                "original_value3": mod.get("original_value3"),
                "original_value4": mod.get("original_value4"),
                "original_value5": mod.get("original_value5"),
                "new_value1": mod.get("new_value1"),
                "new_value2": mod.get("new_value2"),
                "new_value3": mod.get("new_value3"),
                "new_value4": mod.get("new_value4"),
                "new_value5": mod.get("new_value5"),
                "crash_type": mod.get("crash_type"),
                "crash_reason": mod.get("crash_reason"),
                "description": mod.get("description"),
                "found_time": mod.get("found_time", "N/A")  # add the discovery time
            })
        
        return triggering_offsets

    def create_matching_results(self, triggering_offsets: List[Dict], ref_crash_type: str) -> List[Dict]:
        """
        create match detection results
        """
        matching_results = []
        
        # normalize the reference version crash type
        normalized_ref_crash_type = self.normalize_crash_type(ref_crash_type)
        
        for offset_info in triggering_offsets:
            # get the crash type of the current offset
            crash_type = offset_info.get('crash_type', 'no_crash')
            normalized_crash_type = self.normalize_crash_type(crash_type)
            
            # check whether it matches
            type_match = normalized_crash_type == normalized_ref_crash_type
            
            # create the description
            description = ""
            found_time = offset_info.get('found_time', 'N/A')
            
            if 'field_name' in offset_info:  # format-aware modification
                try:
                    description = f"format-aware modification: {offset_info['field_name']}(offset 0x{int(offset_info['offset']):02X}): {offset_info['original_value']} -> {offset_info['new_value']} triggers {crash_type} vulnerability (discovery time: {found_time})"
                except (ValueError, TypeError):
                    description = f"format-aware modification: offset{offset_info['offset']}: {offset_info['original_value']} -> {offset_info['new_value']} triggers {crash_type} vulnerability (discovery time: {found_time})"
            elif 'offset' in offset_info:  # single offset
                try:
                    description = f"single offset: offset 0x{int(offset_info['offset']):02X}: 0x{int(offset_info['original_value']):02X} -> 0x{int(offset_info['new_value']):02X} triggers {crash_type} vulnerability (discovery time: {found_time})"
                except (ValueError, TypeError):
                    description = f"single offset: offset{offset_info['offset']}: 0x{offset_info['original_value']:02X} -> 0x{offset_info['new_value']:02X} triggers {crash_type} vulnerability (discovery time: {found_time})"
            elif 'offset1' in offset_info and 'offset5' in offset_info:  # quintuple offset
                try:
                    offset2_val = offset_info.get('offset2', 'N/A')
                    offset3_val = offset_info.get('offset3', 'N/A')
                    offset4_val = offset_info.get('offset4', 'N/A')
                    offset5_val = offset_info.get('offset5', 'N/A')
                    if isinstance(offset2_val, str) or offset2_val is None:
                        description = f"quintuple offset: offset 0x{int(offset_info['offset1']):02X},0x{offset2_val},0x{offset3_val},0x{offset4_val},0x{offset5_val}: (0x{int(offset_info['original_value1']):02X},0x{int(offset_info['original_value2']):02X},0x{int(offset_info['original_value3']):02X},0x{int(offset_info['original_value4']):02X},0x{int(offset_info['original_value5']):02X}) -> (0x{int(offset_info['new_value1']):02X},0x{int(offset_info['new_value2']):02X},0x{int(offset_info['new_value3']):02X},0x{int(offset_info['new_value4']):02X},0x{int(offset_info['new_value5']):02X}) triggers {crash_type} vulnerability (discovery time: {found_time})"
                    else:
                        description = f"quintuple offset: offset 0x{int(offset_info['offset1']):02X},0x{int(offset2_val):02X},0x{int(offset3_val):02X},0x{int(offset4_val):02X},0x{int(offset5_val):02X}: (0x{int(offset_info['original_value1']):02X},0x{int(offset_info['original_value2']):02X},0x{int(offset_info['original_value3']):02X},0x{int(offset_info['original_value4']):02X},0x{int(offset_info['original_value5']):02X}) -> (0x{int(offset_info['new_value1']):02X},0x{int(offset_info['new_value2']):02X},0x{int(offset_info['new_value3']):02X},0x{int(offset_info['new_value4']):02X},0x{int(offset_info['new_value5']):02X}) triggers {crash_type} vulnerability (discovery time: {found_time})"
                except (ValueError, TypeError):
                    description = f"quintuple offset: offset{offset_info['offset1']},{offset_info.get('offset2', 'N/A')},{offset_info.get('offset3', 'N/A')},{offset_info.get('offset4', 'N/A')},{offset_info.get('offset5', 'N/A')}: ({offset_info['original_value1']},{offset_info['original_value2']},{offset_info['original_value3']},{offset_info['original_value4']},{offset_info['original_value5']}) -> ({offset_info['new_value1']},{offset_info['new_value2']},{offset_info['new_value3']},{offset_info['new_value4']},{offset_info['new_value5']}) triggers {crash_type} vulnerability (discovery time: {found_time})"
            elif 'offset1' in offset_info and 'offset4' in offset_info:  # quadruple offset
                try:
                    offset2_val = offset_info.get('offset2', 'N/A')
                    offset3_val = offset_info.get('offset3', 'N/A')
                    offset4_val = offset_info.get('offset4', 'N/A')
                    if isinstance(offset2_val, str) or offset2_val is None:
                        description = f"quadruple offset: offset 0x{int(offset_info['offset1']):02X},0x{offset2_val},0x{offset3_val},0x{offset4_val}: (0x{int(offset_info['original_value1']):02X},0x{int(offset_info['original_value2']):02X},0x{int(offset_info['original_value3']):02X},0x{int(offset_info['original_value4']):02X}) -> (0x{int(offset_info['new_value1']):02X},0x{int(offset_info['new_value2']):02X},0x{int(offset_info['new_value3']):02X},0x{int(offset_info['new_value4']):02X}) triggers {crash_type} vulnerability (discovery time: {found_time})"
                    else:
                        description = f"quadruple offset: offset 0x{int(offset_info['offset1']):02X},0x{int(offset2_val):02X},0x{int(offset3_val):02X},0x{int(offset4_val):02X}: (0x{int(offset_info['original_value1']):02X},0x{int(offset_info['original_value2']):02X},0x{int(offset_info['original_value3']):02X},0x{int(offset_info['original_value4']):02X}) -> (0x{int(offset_info['new_value1']):02X},0x{int(offset_info['new_value2']):02X},0x{int(offset_info['new_value3']):02X},0x{int(offset_info['new_value4']):02X}) triggers {crash_type} vulnerability (discovery time: {found_time})"
                except (ValueError, TypeError):
                    description = f"quadruple offset: offset{offset_info['offset1']},{offset_info.get('offset2', 'N/A')},{offset_info.get('offset3', 'N/A')},{offset_info.get('offset4', 'N/A')}: ({offset_info['original_value1']},{offset_info['original_value2']},{offset_info['original_value3']},{offset_info['original_value4']}) -> ({offset_info['new_value1']},{offset_info['new_value2']},{offset_info['new_value3']},{offset_info['new_value4']}) triggers {crash_type} vulnerability (discovery time: {found_time})"
            elif 'offset1' in offset_info and 'offset3' in offset_info:  # triple offset
                try:
                    offset2_val = offset_info.get('offset2', 'N/A')
                    offset3_val = offset_info.get('offset3', 'N/A')
                    if isinstance(offset2_val, str) or offset2_val is None:
                        description = f"triple offset: offset 0x{int(offset_info['offset1']):02X},0x{offset2_val},0x{offset3_val}: (0x{int(offset_info['original_value1']):02X},0x{int(offset_info['original_value2']):02X},0x{int(offset_info['original_value3']):02X}) -> (0x{int(offset_info['new_value1']):02X},0x{int(offset_info['new_value2']):02X},0x{int(offset_info['original_value3']):02X}) triggers {crash_type} vulnerability (discovery time: {found_time})"
                    else:
                        description = f"triple offset: offset 0x{int(offset_info['offset1']):02X},0x{int(offset2_val):02X},0x{int(offset3_val):02X}: (0x{int(offset_info['original_value1']):02X},0x{int(offset_info['original_value2']):02X},0x{int(offset_info['original_value3']):02X}) -> (0x{int(offset_info['new_value1']):02X},0x{int(offset_info['new_value2']):02X},0x{int(offset_info['original_value3']):02X}) triggers {crash_type} vulnerability (discovery time: {found_time})"
                except (ValueError, TypeError):
                    description = f"triple offset: offset{offset_info['offset1']},{offset_info.get('offset2', 'N/A')},{offset_info.get('offset3', 'N/A')}: ({offset_info['original_value1']},{offset_info['original_value2']},{offset_info['original_value3']}) -> ({offset_info['new_value1']},{offset_info['new_value2']},{offset_info['new_value3']}) triggers {crash_type} vulnerability (discovery time: {found_time})"
            elif 'offset1' in offset_info:  # double offset
                try:
                    offset2_val = offset_info.get('offset2', 'N/A')
                    if isinstance(offset2_val, str) or offset2_val is None:
                        description = f"double offset: offset 0x{int(offset_info['offset1']):02X},0x{offset2_val}: (0x{int(offset_info['original_value1']):02X},0x{int(offset_info['original_value2']):02X}) -> (0x{int(offset_info['new_value1']):02X},0x{int(offset_info['new_value2']):02X}) triggers {crash_type} vulnerability (discovery time: {found_time})"
                    else:
                        description = f"double offset: offset 0x{int(offset_info['offset1']):02X},0x{int(offset2_val):02X}: (0x{int(offset_info['original_value1']):02X},0x{int(offset_info['original_value2']):02X}) -> (0x{int(offset_info['new_value1']):02X},0x{int(offset_info['new_value2']):02X}) triggers {crash_type} vulnerability (discovery time: {found_time})"
                except (ValueError, TypeError):
                    description = f"double offset: offset{offset_info['offset1']},{offset_info.get('offset2', 'N/A')}: ({offset_info['original_value1']},{offset_info['original_value2']}) -> ({offset_info['new_value1']},{offset_info['new_value2']}) triggers {crash_type} vulnerability (discovery time: {found_time})"
            
            match_info = {
                "offset_info": offset_info,
                "type_match": type_match,
                "is_match": type_match,  # type match means it is a match
                "description": description
            }
            
            matching_results.append(match_info)
        
        return matching_results

    def normalize_crash_type(self, crash_type: str) -> str:
        """
        normalize crash types so that similar types match
        """
        if crash_type is None:
            return "unknown"
        
        # remove hyphens and convert to lowercase for better matching
        normalized = crash_type.lower().replace("-", "_").replace(" ", "_")
        
        # define the similar type mapping
        type_mappings = {
            "heap_buffer_overflow": "heap_buffer_overflow",
            "heap_buffer_overflow": "heap_buffer_overflow",
            "stack_buffer_overflow": "stack_buffer_overflow",
            "stack_buffer_overflow": "stack_buffer_overflow",
            "segfault": "segv",
            "segv": "segfault",
            "other_crash": "other_crash",
            "heap-buffer-overflow": "heap_buffer_overflow",
            "stack-buffer-overflow": "stack_buffer_overflow",
            "heap_buffer_overflow": "heap_buffer_overflow",
            "heap_buffer_overflow": "heap_buffer_overflow",
            "use_after_free": "use_after_free",
            "use_after_free": "use_after_free",
            "double_free": "double_free",
            "double_free": "double_free",
            "global_buffer_overflow": "global_buffer_overflow",
            "global_buffer_overflow": "global_buffer_overflow",
            "stack_overflow": "stack_overflow",
            "stack_overflow": "stack_overflow",
            "floating_point_exception": "floating_point_exception",
            "divide_by_zero": "divide_by_zero"
        }
        
        return type_mappings.get(normalized, normalized)

    def find_best_match(self, matching_results: List[Dict]) -> Optional[Dict]:
        """
        find the best match result
        """
        if not matching_results:
            return None
        
        # prefer type matches
        for match in matching_results:
            if match['is_match']:
                return match
        
        return None

    def generate_recommendations(self, triggering_offsets: List[Dict], matching_results: List[Dict]) -> List[str]:
        """
        generate analysis suggestions
        """
        recommendations = []
        
        best_match = self.find_best_match(matching_results)
        if best_match:
            recommendations.append("found offset positions matching the reference version:")
            recommendations.append(f"  - {best_match['description']}")
            recommendations.append("recommend using the modification value at this offset position to make the target version trigger the same vulnerability as the reference version")
        else:
            recommendations.append("no offset position fully matching the reference version found")
            recommendations.append("recommend manually analyzing the modification effects of the following offset positions:")
        
        if not best_match and triggering_offsets:
            recommendations.append("offset positions that can trigger the same vulnerability:")
            for info in triggering_offsets:
                recommendations.append(f"  - {info['description']}")
        
        if not triggering_offsets:
            recommendations.append("no effective offset position modification scheme found to trigger the same vulnerability")
            recommendations.append("deeper analysis or modifying multiple offset positions may be needed")
        
        return recommendations

    def save_important_results(self, final_result: Dict):
        """save important results to a specified file"""
        print(f"save important results to: {self.result_file_path}")
        
        # create the directory
        self.result_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # extract the important results
        _fp_loc = final_result.get("fork_point_location")
        if not _fp_loc or _fp_loc == "Unknown":
            _fp_loc = final_result.get("fork_point_analysis", {}).get("fork_point_info", {}).get("target_crash_function", {}).get("file_line", "Unknown") if final_result.get("fork_point_analysis", {}).get("fork_point_info", {}) and 'target_crash_function' in final_result.get("fork_point_analysis", {}).get("fork_point_info", {}) else "Unknown"
        important_results = {
            "fork_point_location": _fp_loc,
            "fork_point_analysis": final_result.get("fork_point_analysis", {}),
            "key_fork_point": final_result.get("key_fork_point", {}),
            "trace_analysis": final_result.get("trace_analysis", {}),
            "fork_point_trigger_analysis": final_result.get("fork_point_trigger_analysis", {}),
            "rr_backward_analysis": final_result.get("rr_backward_analysis", {})
        }
        
        # extract key information from the triggering analysis
        trigger_analysis = final_result.get("fork_point_trigger_analysis", {})
        if trigger_analysis:
            important_results["triggering_offsets"] = trigger_analysis.get("triggering_offsets", [])
            important_results["matching_results"] = trigger_analysis.get("matching_results", [])
            important_results["best_match"] = trigger_analysis.get("best_match", {})
            important_results["summary"] = trigger_analysis.get("summary", {})
        
        # extract key information from the rr analysis
        rr_analysis = final_result.get("rr_backward_analysis", {})
        if rr_analysis:
            important_results["rr_analysis"] = rr_analysis
        
        # save the results
        with open(self.result_file_path, 'w', encoding='utf-8') as f:
            json.dump(important_results, f, indent=2, ensure_ascii=False)
        
        print(f"important results saved to: {self.result_file_path}")
        
        # print the summary
        print("\n=== Important results summary ===")
        print(f"fork point location: {important_results['fork_point_location']}")
        
        # count all offset positions that can trigger the same vulnerability
        triggering_count = 0
        if important_results.get("matching_results"):
            for match_result in important_results["matching_results"]:
                if match_result.get("is_match", False):
                    triggering_count += 1
        
        print(f"number of offset positions that can trigger the same vulnerability: {triggering_count}")
        
        # print the match results
        matching_results = important_results.get("matching_results", [])
        if matching_results:
            print(f"\nMatch results:")
            ref_crash_type = self.extract_crash_type(self.ref_trace.get("stderr", ""))
            print(f"reference version crash type: {ref_crash_type}")
            
            matched_results = [result for result in matching_results if result.get("is_match", False)]
            if matched_results:
                print(f"found {len(matched_results)} matching offset positions:")
                for result in matched_results:
                    offset_info = result.get("offset_info", {})
                    
                    # output the matching results
                    if 'field_name' in offset_info:  # format-aware modification
                        original_value = offset_info.get("original_value", 0)
                        new_value = offset_info.get("new_value", 0)
                        offset = offset_info.get("offset", 0)
                        field_name = offset_info.get("field_name", "unknown")
                        new_crash_type = offset_info.get("crash_type", "unknown")
                        found_time = offset_info.get("found_time", "N/A")
                        print(f"  - format-aware modification: {field_name}(offset position: 0x{offset:02X}), modification value: {original_value} -> {new_value}, crash type: {new_crash_type} (discovery time: {found_time})")
                    elif 'offset' in offset_info:  # single offset
                        original_value = offset_info.get("original_value", 0)
                        new_value = offset_info.get("new_value", 0)
                        offset = offset_info.get("offset", 0)
                        new_crash_type = offset_info.get("crash_type", "unknown")
                        found_time = offset_info.get("found_time", "N/A")
                        print(f"  - single offset: offset position: 0x{offset:02X}, modification value: 0x{original_value:02X} -> 0x{new_value:02X}, crash type: {new_crash_type} (discovery time: {found_time})")
                    elif 'offset1' in offset_info and 'offset5' in offset_info:  # quintuple offset
                        original_value1 = offset_info.get("original_value1", 0)
                        new_value1 = offset_info.get("new_value1", 0)
                        original_value2 = offset_info.get("original_value2", 0)
                        new_value2 = offset_info.get("new_value2", 0)
                        original_value3 = offset_info.get("original_value3", 0)
                        new_value3 = offset_info.get("new_value3", 0)
                        original_value4 = offset_info.get("original_value4", 0)
                        new_value4 = offset_info.get("new_value4", 0)
                        original_value5 = offset_info.get("original_value5", 0)
                        new_value5 = offset_info.get("new_value5", 0)
                        offset1 = offset_info.get("offset1", 0)
                        offset2 = offset_info.get("offset2", 0)
                        offset3 = offset_info.get("offset3", 0)
                        offset4 = offset_info.get("offset4", 0)
                        offset5 = offset_info.get("offset5", 0)
                        new_crash_type = offset_info.get("crash_type", "unknown")
                        found_time = offset_info.get("found_time", "N/A")
                        print(f"  - quintuple offset: offset position: 0x{offset1:02X},0x{offset2:02X},0x{offset3:02X},0x{offset4:02X},0x{offset5:02X}, modification value: (0x{original_value1:02X},0x{original_value2:02X},0x{original_value3:02X},0x{original_value4:02X},0x{original_value5:02X}) -> (0x{new_value1:02X},0x{new_value2:02X},0x{new_value3:02X},0x{new_value4:02X},0x{new_value5:02X}), crash type: {new_crash_type} (discovery time: {found_time})")
                    elif 'offset1' in offset_info and 'offset4' in offset_info:  # quadruple offset
                        original_value1 = offset_info.get("original_value1", 0)
                        new_value1 = offset_info.get("new_value1", 0)
                        original_value2 = offset_info.get("original_value2", 0)
                        new_value2 = offset_info.get("new_value2", 0)
                        original_value3 = offset_info.get("original_value3", 0)
                        new_value3 = offset_info.get("new_value3", 0)
                        original_value4 = offset_info.get("original_value4", 0)
                        new_value4 = offset_info.get("new_value4", 0)
                        offset1 = offset_info.get("offset1", 0)
                        offset2 = offset_info.get("offset2", 0)
                        offset3 = offset_info.get("offset3", 0)
                        offset4 = offset_info.get("offset4", 0)
                        new_crash_type = offset_info.get("crash_type", "unknown")
                        found_time = offset_info.get("found_time", "N/A")
                        print(f"  - quadruple offset: offset position: 0x{offset1:02X},0x{offset2:02X},0x{offset3:02X},0x{offset4:02X}, modification value: (0x{original_value1:02X},0x{original_value2:02X},0x{original_value3:02X},0x{original_value4:02X}) -> (0x{new_value1:02X},0x{new_value2:02X},0x{new_value3:02X},0x{new_value4:02X}), crash type: {new_crash_type} (discovery time: {found_time})")
                    elif 'offset1' in offset_info and 'offset3' in offset_info:  # triple offset
                        original_value1 = offset_info.get("original_value1", 0)
                        new_value1 = offset_info.get("new_value1", 0)
                        original_value2 = offset_info.get("original_value2", 0)
                        new_value2 = offset_info.get("new_value2", 0)
                        original_value3 = offset_info.get("original_value3", 0)
                        new_value3 = offset_info.get("new_value3", 0)
                        offset1 = offset_info.get("offset1", 0)
                        offset2 = offset_info.get("offset2", 0)
                        offset3 = offset_info.get("offset3", 0)
                        new_crash_type = offset_info.get("crash_type", "unknown")
                        found_time = offset_info.get("found_time", "N/A")
                        print(f"  - triple offset: offset position: 0x{offset1:02X},0x{offset2:02X},0x{offset3:02X}, modification value: (0x{original_value1:02X},0x{original_value2:02X},0x{original_value3:02X}) -> (0x{new_value1:02X},0x{new_value2:02X},0x{new_value3:02X}), crash type: {new_crash_type} (discovery time: {found_time})")
                    elif 'offset1' in offset_info:  # double offset
                        original_value1 = offset_info.get("original_value1", 0)
                        new_value1 = offset_info.get("new_value1", 0)
                        original_value2 = offset_info.get("original_value2", 0)
                        new_value2 = offset_info.get("new_value2", 0)
                        offset1 = offset_info.get("offset1", 0)
                        offset2 = offset_info.get("offset2", 0)
                        new_crash_type = offset_info.get("crash_type", "unknown")
                        found_time = offset_info.get("found_time", "N/A")
                        print(f"  - double offset: offset position: 0x{offset1:02X},0x{offset2:02X}, modification value: (0x{original_value1:02X},0x{original_value2:02X}) -> (0x{new_value1:02X},0x{new_value2:02X}), crash type: {new_crash_type} (discovery time: {found_time})")
            else:
                print("no offset position matching the reference version crash type found")
        else:
            print("no matching offset position found")
        
        # print the rr analysis results summary
        rr_analysis = important_results.get("rr_analysis", {})
        if rr_analysis:
            print(f"\nRR reverse analysis results:")
            print(f"  analysis status: {rr_analysis.get('analysis_status', 'unknown')}")
            print(f"  number of successfully analyzed variables: {rr_analysis.get('successful_analyses', 0)}/{rr_analysis.get('total_variables_analyzed', 0)}")
            if rr_analysis.get('individual_results'):
                for var, result in rr_analysis['individual_results'].items():
                    if 'error' not in result:
                        print(f"  - variable {var}: analyzed successfully")
                    else:
                        print(f"  - variable {var}: analysis failed - {result['error']}")

    def combine_analyses(self, fork_analysis: Dict, trace_analysis: Dict) -> Dict:
        """merge the fork point analysis and traceability analysis results"""
        combined = {
            "fork_point_summary": fork_analysis.get("description", ""),
            "crash_location": trace_analysis["crash_location"] if trace_analysis else "N/A",
            "root_cause": trace_analysis["root_cause_analysis"] if trace_analysis else "N/A",
            "modification_suggestions": trace_analysis["modification_suggestions"]["modifications"] if trace_analysis else [],
            "recommendation": "modify the input file according to the traceability analysis results to make the execution paths of the two versions consistent"
        }
        return combined

    def print_time_summary(self):
        """print the time summary"""
        print(f"\n=== Time summary ===")
        if self.compile_end_time and self.compile_start_time:
            compile_time = self.compile_end_time - self.compile_start_time
            print(f"compile time: {compile_time:.2f}seconds")
        print(f"trace comparison time: {self.trace_comparison_time:.2f}seconds")
        print(f"fork point analysis time: {self.fork_point_analysis_time:.2f}seconds")
        print(f"traceability analysis time: {self.tracer_analysis_time:.2f}seconds")
        print(f"fork point triggering analysis time: {self.fork_point_trigger_analysis_time:.2f}seconds")
        print(f"total time: {self.total_time:.2f}seconds")

    def cleanup(self):
        """clean up temporary files"""
        print(f"clean up temporary files: {self.work_dir}")
        shutil.rmtree(self.work_dir, ignore_errors=True)


class UniversalTracerAnalyzer:
    def __init__(self, reference_version_path: str, target_version_path: str, 
                 input_file: str, crash_location: Dict[str, Any],
                 target_build_dir: str, reference_build_dir: str, execution_config: Dict):
        self.reference_version_path = Path(reference_version_path)
        self.target_version_path = Path(target_version_path)
        self.input_file = Path(input_file)
        self.crash_file = Path(crash_location["file"])  # keep as a Path object
        self.crash_line = int(crash_location["line"])
        self.function = crash_location.get("function", "")
        
        # add build directory paths
        self.target_build_dir = Path(target_build_dir)
        self.reference_build_dir = Path(reference_build_dir)
        
        # add execution config
        self.execution_config = execution_config
        
        self.work_dir = Path(tempfile.mkdtemp(prefix="trace_analysis_"))
        self.results_dir = self.work_dir / "results"
        self.results_dir.mkdir(exist_ok=True)
        
        # timing variables
        self.start_time = None
        self.total_time = 0

    def start_timer(self):
        """start timing"""
        self.start_timer = time.time()

    def stop_timer(self):
        """stop timing"""
        if self.start_timer:
            self.total_time = time.time() - self.start_timer
            print(f"total time: {self.total_time:.2f}seconds")

    def read_crash_source_code(self) -> str:
        """read the source code at the crash location"""
        try:
            # try to read the file from the original source directory
            # first try to find it in the reference version path
            ref_file_path = self.reference_version_path / self.crash_file.name
            if not ref_file_path.exists():
                # if it does not exist in the reference version path, try to find it in the target version path
                target_file_path = self.target_version_path / self.crash_file.name
                if target_file_path.exists():
                    ref_file_path = target_file_path
                else:
                    # if it is still not found, try to find it in the build directory
                    for root, dirs, files in os.walk(self.reference_build_dir):
                        for file in files:
                            if file == self.crash_file.name:
                                ref_file_path = Path(root) / file
                                break
                    if not ref_file_path.exists():
                        # finally try to use the crash file path directly
                        ref_file_path = self.crash_file
            
            with open(ref_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # get the complete statement (search up/down from the crash line for the complete statement)
            complete_statement_lines = self.get_complete_statement(lines, self.crash_line)
            
            source_code = ""
            for line_num, line_content in complete_statement_lines:
                marker = ">>> " if line_num == self.crash_line else "    "
                source_code += f"{marker}{line_num:4d}: {line_content}"
            
            return source_code
        except Exception as e:
            print(f"failed to read source code: {e}")
            # try to find the corresponding source file in the build directory
            try:
                # iterate over the build directory to find a matching source file
                for root, dirs, files in os.walk(self.reference_build_dir):
                    for file in files:
                        if file.endswith('.c') or file.endswith('.cpp') or file.endswith('.h'):
                            if self.crash_file.name in file:
                                actual_path = Path(root) / file
                                print(f"using file from the build directory: {actual_path}")
                                with open(actual_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    lines = f.readlines()
                                
                                # get the complete statement
                                complete_statement_lines = self.get_complete_statement(lines, self.crash_line)
                                
                                source_code = ""
                                for line_num, line_content in complete_statement_lines:
                                    marker = ">>> " if line_num == self.crash_line else "    "
                                    source_code += f"{marker}{line_num:4d}: {line_content}"
                                
                                return source_code
            except Exception as e2:
                print(f"reading source code from the build directory also failed: {e2}")
            return ""

    def get_complete_statement(self, lines: List[str], crash_line: int) -> List[Tuple[int, str]]:
        """
        get the complete statement at the crash location
        """
        # find the start and end lines of the statement
        start_line = crash_line - 1  # 0-based index
        end_line = crash_line - 1
        
        # search upward for the statement start (find the beginning of the statement)
        statement_start = start_line
        bracket_count = 0
        paren_count = 0
        
        # priority: find the statement terminator (semicolon) or the statement start (e.g. if, for, while, function call, etc.)
        for i in range(start_line, -1, -1):
            line = lines[i].strip()
            if line == "":
                continue
                
            # check whether it is the start of a statement
            if re.search(r'\b(if|for|while|return|switch|case|default|do|else|try|catch|throw)\b', line):
                statement_start = i
                break
            elif line.endswith(';') or line.endswith('{') or line.endswith('}') or line.startswith('#'):
                # if the current line ends with a semicolon, a brace, or is a preprocessor directive, then the previous line is the end of the statement
                if i < start_line:
                    statement_start = i + 1
                break
            elif line.startswith('}'):
                # if it is }, it may be the end of a block and we need to find the matching {
                bracket_count += 1
                continue
            elif line.endswith('{'):
                # if it is {, it may be the start of a block
                bracket_count -= 1
                if bracket_count == 0:
                    statement_start = i
                    break
            elif '(' in line and ')' in line:
                # if it is a function call or an expression
                statement_start = i
                break
            elif i == 0:
                # if the beginning of the file is reached, start from here
                statement_start = 0
        
        # search downward for the statement end
        statement_end = end_line
        for i in range(end_line, len(lines)):
            line = lines[i].strip()
            if line == "":
                continue
                
            # check whether it is the end of a statement
            if line.endswith(';') or line.endswith('}') or line.startswith('}'):
                statement_end = i
                break
            elif line.endswith('{'):
                # if it is {, we need to find the matching }
                bracket_count = 1
                for j in range(i + 1, len(lines)):
                    sub_line = lines[j].strip()
                    if sub_line.startswith('{'):
                        bracket_count += 1
                    elif sub_line.startswith('}'):
                        bracket_count -= 1
                        if bracket_count == 0:
                            statement_end = j
                            break
                break
            elif line.endswith(')'):
                # if it is the end of a function call or expression
                paren_count = 0
                for char in line:
                    if char == '(':
                        paren_count += 1
                    elif char == ')':
                        paren_count -= 1
                if paren_count == 0:
                    statement_end = i
                    break
            elif i == len(lines) - 1:
                # if the end of the file is reached, end here
                statement_end = i
        
        # return all lines within the statement range
        result = []
        for i in range(max(0, statement_start), min(len(lines), statement_end + 1)):
            result.append((i + 1, lines[i]))
        
        return result

    def analyze_crash_code(self) -> Dict:
        """analyze the code at the crash location and identify possible fork causes"""
        try:
            # try to read the file from the original source directory
            ref_file_path = self.reference_version_path / self.crash_file.name
            if not ref_file_path.exists():
                # if it does not exist in the reference version path, try to find it in the target version path
                target_file_path = self.target_version_path / self.crash_file.name
                if target_file_path.exists():
                    ref_file_path = target_file_path
                else:
                    # if it is still not found, try to find it in the build directory
                    for root, dirs, files in os.walk(self.reference_build_dir):
                        for file in files:
                            if file == self.crash_file.name:
                                ref_file_path = Path(root) / file
                                break
                    if not ref_file_path.exists():
                        # finally try to use the crash file path directly
                        ref_file_path = self.crash_file
            
            with open(ref_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()
        except Exception:
            # if the source file cannot be found, try to find it in the build directory
            try:
                for root, dirs, files in os.walk(self.reference_build_dir):
                    for file in files:
                        if file.endswith('.c') or file.endswith('.cpp') or file.endswith('.h'):
                            if self.crash_file.name in file:
                                actual_path = Path(root) / file
                                print(f"using file from the build directory: {actual_path}")
                                with open(actual_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    all_lines = f.readlines()
                                break
            except Exception:
                return {"error": "unable to read the source file", "file_path": str(self.crash_file)}

        analysis_result = {
            "line_number": self.crash_line,
            "file_path": str(self.crash_file),  # convert to string
            "code_snippet": "",
            "potential_causes": [],
            "analysis": {}
        }
        
        # get the code of the crash line
        if 0 <= self.crash_line - 1 < len(all_lines):
            crash_line_code = all_lines[self.crash_line - 1].strip()
            analysis_result["code_snippet"] = crash_line_code
            
            # check whether it is a division-by-zero operation
            if '/' in crash_line_code and ('0' in crash_line_code or '0x0' in crash_line_code or 'NULL' in crash_line_code):
                analysis_result["potential_causes"].append("division by zero")
                analysis_result["analysis"]["type"] = "division_by_zero"
                analysis_result["analysis"]["operation"] = crash_line_code
                print(f"detected a possible division-by-zero operation: {crash_line_code}")
            
            # check whether it is a conditional
            elif re.search(r'if\s*\(|while\s*\(|for\s*\(', crash_line_code):
                analysis_result["potential_causes"].append("different conditional")
                analysis_result["analysis"]["type"] = "condition"
                analysis_result["analysis"]["condition"] = crash_line_code
                print(f"detected a conditional: {crash_line_code}")
            
            # check whether it is a memory access
            elif re.search(r'\[.*\]|->|\.|malloc|new|free', crash_line_code):
                analysis_result["potential_causes"].append("memory access/calculation method differs")
                analysis_result["analysis"]["type"] = "memory_access"
                analysis_result["analysis"]["operation"] = crash_line_code
                print(f"detected a memory operation: {crash_line_code}")
            
            # check whether it is a function call
            elif re.search(r'[a-zA-Z_][a-zA-Z0-9_]*\s*\(', crash_line_code):
                analysis_result["potential_causes"].append("function call/parameters differ")
                analysis_result["analysis"]["type"] = "function_call"
                analysis_result["analysis"]["function"] = crash_line_code
                print(f"detected a function call: {crash_line_code}")
        
        return analysis_result

    def find_related_variables(self, source_code: str) -> List[str]:
        """find variables related to the crash line"""
        lines = source_code.split('\n')
        related_vars = set()
        
        for line in lines:
            if f">>> {self.crash_line:4d}:" in line:
                crash_code = line.split(':', 2)[-1].strip()
                
                # extract variable names (simple regex match)
                var_matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', crash_code)
                for var in var_matches:
                    if var not in ['if', 'while', 'for', 'return', 'int', 'char', 'void', 'const', 'struct', 'class', 'static']:
                        related_vars.add(var)
        
        return list(related_vars)

    def find_variable_definitions(self, related_vars: List[str]) -> Dict[str, List[str]]:
        """find the definition and assignment positions of variables in the source file"""
        var_definitions = {}
        
        try:
            # try to read the file from the original source directory
            ref_file_path = self.reference_version_path / self.crash_file.name
            if not ref_file_path.exists():
                # if it does not exist in the reference version path, try to find it in the target version path
                target_file_path = self.target_version_path / self.crash_file.name
                if target_file_path.exists():
                    ref_file_path = target_file_path
                else:
                    # if it is still not found, try to find it in the build directory
                    for root, dirs, files in os.walk(self.reference_build_dir):
                        for file in files:
                            if file == self.crash_file.name:
                                ref_file_path = Path(root) / file
                                break
                    if not ref_file_path.exists():
                        # finally try to use the crash file path directly
                        ref_file_path = self.crash_file
            
            with open(ref_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()
            
            # find the definition and assignment of each related variable
            for var in related_vars:
                var_definitions[var] = []
                
                for i, line in enumerate(all_lines):
                    line_num = i + 1
                    if var in line and '=' in line:
                        # check whether it is an assignment statement
                        if re.search(rf'\b{var}\s*=', line):
                            var_definitions[var].append(f"Line {line_num}: {line.strip()}")
                    
                    # find variable declarations
                    if re.search(rf'(int|char|short|long|double|float|bool|size_t)\s+.*\b{var}\b', line):
                        var_definitions[var].append(f"Line {line_num}: {line.strip()}")
        
        except Exception as e:
            print(f"failed to find variable definitions: {e}")
        
        return var_definitions

    def analyze_version_differences(self) -> Dict:
        """analyze the code differences between the two versions at the crash location"""
        print("Analyzing the code differences between the two versions at the crash location...")
        
        # try to find the original source path
        try:
            # start searching from the crash file name
            ref_file_path = self.reference_version_path / self.crash_file.name
            target_file_path = self.target_version_path / self.crash_file.name
            
            # if the file does not exist, try to find it in the build directory
            if not ref_file_path.exists():
                for root, dirs, files in os.walk(self.reference_build_dir):
                    for file in files:
                        if file.endswith('.c') or file.endswith('.cpp') or file.endswith('.h'):
                            if self.crash_file.name in file:
                                ref_file_path = Path(root) / file
                                break
                if not ref_file_path.exists():
                    print(f"Warning: unable to find the reference version source file: {self.crash_file.name}")
                    return {
                        "error": "unable to find the reference version source file",
                        "file_path": str(self.crash_file),
                        "crash_line": self.crash_line
                    }
            
            if not target_file_path.exists():
                for root, dirs, files in os.walk(self.target_build_dir):
                    for file in files:
                        if file.endswith('.c') or file.endswith('.cpp') or file.endswith('.h'):
                            if self.crash_file.name in file:
                                target_file_path = Path(root) / file
                                break
                if not target_file_path.exists():
                    print(f"Warning: unable to find the target version source file: {self.crash_file.name}")
                    return {
                        "error": "unable to find the target version source file",
                        "file_path": str(self.crash_file),
                        "crash_line": self.crash_line
                    }
        
        except Exception as e:
            print(f"failed to determine the source file path: {e}")
            return {
                "error": f"failed to determine the source file path: {e}",
                "file_path": str(self.crash_file),
                "crash_line": self.crash_line
            }
        
        print(f"target version source file: {target_file_path}")
        print(f"reference version source file: {ref_file_path}")
        
        differences = {
            "file_path": str(self.crash_file.name),
            "crash_line": self.crash_line,
            "target_code": "",
            "reference_code": "",
            "line_differences": [],
            "complete_statement_differences": [],
            "additional_checks": []  # new field to store additional checks
        }
        
        try:
            # read the target version code
            with open(target_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                target_lines = f.readlines()
            
            # read the reference version code
            with open(ref_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                ref_lines = f.readlines()
            
            # get the code of the crash line
            target_crash_line_code = target_lines[self.crash_line - 1].strip() if self.crash_line <= len(target_lines) else ""
            ref_crash_line_code = ref_lines[self.crash_line - 1].strip() if self.crash_line <= len(ref_lines) else ""
            
            differences["target_code"] = target_crash_line_code
            differences["reference_code"] = ref_crash_line_code
            
            print(f"target version crash line: {target_crash_line_code}")
            print(f"reference version crash line: {ref_crash_line_code}")
            
            # get the complete statement
            target_complete_statement = self.get_complete_statement(target_lines, self.crash_line)
            ref_complete_statement = self.get_complete_statement(ref_lines, self.crash_line)
            
            target_complete_str = "\n".join([line for _, line in target_complete_statement])
            ref_complete_str = "\n".join([line for _, line in ref_complete_statement])
            
            print(f"target version complete statement:\n{target_complete_str}")
            print(f"reference version complete statement:\n{ref_complete_str}")
            
            # compare the differences between the two lines of code
            if target_crash_line_code != ref_crash_line_code:
                differences["line_differences"].append({
                    "type": "code_difference",
                    "target_line": target_crash_line_code,
                    "reference_line": ref_crash_line_code
                })
                print("found code differences!")
            else:
                print("crash line code is the same")
            
            # compare the differences between the complete statements
            if target_complete_str != ref_complete_str:
                differences["complete_statement_differences"].append({
                    "type": "complete_statement_difference",
                    "target_statement": target_complete_str,
                    "reference_statement": ref_complete_str
                })
                print("found complete statement differences!")
            else:
                print("complete statements are the same")
                
            # extra check: find whether the target version added check code
            target_complete_lines = [line for _, line in target_complete_statement]
            ref_complete_lines = [line for _, line in ref_complete_statement]
            
            # check whether the target version added check code (e.g. bounds checks, error handling, etc.)
            for t_line in target_complete_lines:
                if re.search(r'if\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*>|<|==|!=|>=|<=\s*', t_line) and \
                   re.search(r'max_|limit_|check|validat|error|return\s*-', t_line.lower()):
                    differences["additional_checks"].append({
                        "type": "security_check_added",
                        "line": t_line.strip(),
                        "description": "the target version added safety check code"
                    })
                    print(f"found new safety check in the target version: {t_line.strip()}")
            
        except Exception as e:
            print(f"failed to analyze version differences: {e}")
            differences["error"] = str(e)
        
        return differences

    def generate_input_modification_suggestions(self, analysis: Dict, differences: Dict) -> Dict:
        """generate input file modification suggestions"""
        suggestions = {
            "type": "input_modification_suggestions",
            "modifications": [],
            "explanation": "",
            "target": "",
            "input_offsets": []
        }
        
        # generate different modification suggestions according to the fork type
        crash_type = analysis.get("analysis", {}).get("type", "unknown")
        
        if crash_type == "condition":
            suggestions["explanation"] = "different conditionals caused the execution paths to fork; modify the input to make the conditionals consistent"
            suggestions["target"] = "variables related to conditional checks"
            
            # find variables involved in the conditional
            condition = analysis["analysis"].get("condition", "")
            var_matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', condition)
            for var in var_matches:
                if var not in ['if', 'while', 'for', 'return', 'int', 'char', 'void', 'const', 'struct', 'class', 'static']:
                    suggestions["modifications"].append(f"modify the value in the input that affects variable '{var}'")
        
        elif crash_type == "memory_access":
            suggestions["explanation"] = "the memory access calculation method differs; modify the input to make the calculation parameters consistent"
            suggestions["target"] = "memory access calculation parameters"
            
            operation = analysis["analysis"].get("operation", "")
            var_matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', operation)
            for var in var_matches:
                if var not in ['if', 'while', 'for', 'return', 'int', 'char', 'void', 'const', 'struct', 'class', 'static']:
                    suggestions["modifications"].append(f"modify the value in the input that affects calculation parameter '{var}'")
        
        elif crash_type == "function_call":
            suggestions["explanation"] = "function call parameters differ; modify the input to make the parameters consistent"
            suggestions["target"] = "function call parameters"
            
            function = analysis["analysis"].get("function", "")
            var_matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', function)
            for var in var_matches:
                if var not in ['if', 'while', 'for', 'return', 'int', 'char', 'void', 'const', 'struct', 'class', 'static']:
                    suggestions["modifications"].append(f"modify the value in the input that affects function parameter '{var}'")
        
        elif crash_type == "division_by_zero":
            suggestions["explanation"] = "division-by-zero error; modify the input to avoid the division-by-zero condition"
            suggestions["target"] = "parameters related to the division-by-zero condition"
            
            operation = analysis["analysis"].get("operation", "")
            var_matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b', operation)
            for var in var_matches:
                if var not in ['if', 'while', 'for', 'return', 'int', 'char', 'void', 'const', 'struct', 'class', 'static']:
                    suggestions["modifications"].append(f"modify the value in the input that affects the division-by-zero condition '{var}' to avoid a zero divisor")
        
        else:
            suggestions["explanation"] = "need to analyze the specific fork cause"
            suggestions["target"] = "fork-point-related variables"
        
        # analyze version differences to provide more specific suggestions
        if differences.get("line_differences"):
            for diff in differences["line_differences"]:
                suggestions["modifications"].append(f"reference version: {diff['reference_line']}")
                suggestions["modifications"].append(f"target version: {diff['target_line']}")
                suggestions["modifications"].append("analyze the differences between the two versions at this line, and modify the input to match the reference version behavior")
        
        if differences.get("complete_statement_differences"):
            for diff in differences["complete_statement_differences"]:
                suggestions["modifications"].append(f"reference version complete statement: {diff['reference_statement']}")
                suggestions["modifications"].append(f"target version complete statement: {diff['target_statement']}")
                suggestions["modifications"].append("analyze the differences between the two versions on the complete statement, and modify the input to match the reference version behavior")
        
        # add suggestions for the extra checks
        if differences.get("additional_checks"):
            for check in differences["additional_checks"]:
                suggestions["modifications"].append(f"target version added safety check: {check['line']}")
                suggestions["modifications"].append("the input may need to be modified to bypass or satisfy these checks")
        
        return suggestions

    def run_analysis(self):
        """run the full traceability analysis"""
        print(f"Start traceability analysis, crash location: {self.crash_file}:{self.crash_line}")
        self.start_timer()
        
        try:
            # 1. Analyze crash code
            print("Analyze crash code...")
            analysis = self.analyze_crash_code()
            print(f"code analysis result: {analysis}")
            
            # 2. read the source code at the crash location
            print("Read source code at crash location...")
            source_code = self.read_crash_source_code()
            print(f"crash code snippet:\n{source_code}")
            
            # 3. Find related variables
            print("Find related variables...")
            related_vars = self.find_related_variables(source_code)
            print(f"related variables: {related_vars}")
            
            # 4. Find variable definitions
            print("Find variable definitions...")
            var_definitions = self.find_variable_definitions(related_vars)
            print(f"variable definitions: {var_definitions}")
            
            # 5. Analyze version differences
            print("Analyze version differences...")
            differences = self.analyze_version_differences()
            print(f"version differences: {differences}")
            
            # 6. Generate input modification suggestions
            print("Generate input modification suggestions...")
            suggestions = self.generate_input_modification_suggestions(analysis, differences)
            print(f"modification suggestions: {suggestions}")
            
            # 7. generate the comprehensive report
            report = {
                "crash_location": f"{self.crash_file}:{self.crash_line}",  # convert to string
                "code_analysis": analysis,
                "variable_analysis": {
                    "related_variables": related_vars,
                    "definitions": var_definitions
                },
                "version_differences": differences,
                "modification_suggestions": suggestions,
                "root_cause_analysis": self.perform_root_cause_analysis(analysis, differences)
            }
            
            print(f"\n=== Comprehensive analysis report ===")
            print(f"crash location: {report['crash_location']}")
            print(f"potential causes: {analysis.get('potential_causes', [])}")
            print(f"related variables: {related_vars}")
            print(f"version differences: {bool(differences.get('line_differences', []) or differences.get('complete_statement_differences', []))}")
            print(f"modification suggestions: {suggestions['modifications']}")
            print(f"root cause: {report['root_cause_analysis']}")
            
            self.stop_timer()
            return report
            
        except Exception as e:
            print(f"an error occurred during analysis: {e}")
            import traceback
            traceback.print_exc()
            self.stop_timer()
            return None

    def perform_root_cause_analysis(self, analysis: Dict, differences: Dict) -> str:
        """run the root cause analysis"""
        root_cause = "unable to determine the root cause"
        
        # analyze the fork type
        crash_type = analysis.get("analysis", {}).get("type", "unknown")
        
        if crash_type == "condition":
            root_cause = "different conditionals caused the execution paths to fork - the input must be modified to make the conditionals consistent"
        elif crash_type == "memory_access":
            root_cause = "the memory access calculation method differs - the input must be modified to make the calculation parameters consistent"
        elif crash_type == "function_call":
            root_cause = "function call parameters differ - the input must be modified to make the parameters consistent"
        elif crash_type == "division_by_zero":
            root_cause = "division by zero - the input must be modified to avoid a zero divisor"
        else:
            root_cause = "unknown fork type"
        
        # if there are version differences, refine further
        if differences.get("line_differences") or differences.get("complete_statement_differences"):
            root_cause += "(caused by code differences between versions)"
        
        # if there are new checks, refine further
        if differences.get("additional_checks"):
            root_cause += ", the target version added a safety check"
        
        return root_cause

    def cleanup(self):
        """clean up temporary files"""
        print(f"clean up temporary files: {self.work_dir}")
        shutil.rmtree(self.work_dir, ignore_errors=True)


def main():
    if len(sys.argv) < 7:
        print("Usage: python universal_modular_analyzer.py <reference version path> <target version path> <input file> <output file> <config module path> <result file path> [command args...]")
        print("Example: python universal_modular_analyzer.py /path/to/ref /path/to/target input.dat output.dat config_audiofile.py results/CVE-2017-6831/audiofile-0.3.3.json arg1 arg2")
        return
    
    ref_version = sys.argv[1]
    target_version = sys.argv[2]
    input_file = sys.argv[3]
    output_file = sys.argv[4]
    config_module_path = sys.argv[5]
    result_file_path = sys.argv[6]
    command_args = sys.argv[7:] if len(sys.argv) > 7 else []
    
    print(f"Reference version: {ref_version}")
    print(f"Target version: {target_version}")
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print(f"Config module: {config_module_path}")
    print(f"Result file: {result_file_path}")
    print(f"Command arguments: {command_args}")
    
    analyzer = UniversalVulnerabilityAnalyzer(
        ref_version, target_version, input_file, output_file, command_args,
        config_module_path, result_file_path
    )
    
    result = analyzer.run_analysis()
    
    if result:
        print(f"\nAnalysis complete! Result file: {result}")
        analyzer.print_time_summary()
    else:
        print("\nanalysis failed")
        analyzer.print_time_summary()


if __name__ == "__main__":
    main()
