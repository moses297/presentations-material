# Introduction to Reverse Engineering

## Overview

This repository accompanies the **"Introduction to Reverse Engineering"** presentation. It provides hands-on examples, useful tools, and step-by-step guidance for analyzing, understanding, and modifying binary files.

## Presentation Summary

Reverse engineering is the process of analyzing a system to understand its design, functionality, and inner workings. In cybersecurity, it is used to:
- Analyze compiled code and binary files.
- Modify program behavior.
- Extract useful information.
- Identify vulnerabilities.

### Key Topics Covered:
1. **Compilation & Execution**
   - How source code turns into machine code.
   - Understanding executables and binary structure.
2. **Reading Binary Files**
   - ASCII and Opcode tables.
   - Extracting strings and structures.
3. **Reverse Engineering Tools**
   - Disassembly and decompilation.
   - Tools like Ghidra, IDA, and more.
4. **Modifying Executables**
   - Changing strings in binary files.
   - Altering program logic by modifying opcodes.

## Files in This Repo

- hello.c, hello.o: The original Hello World example.
- hello_hack.o: The modified version after changes.
- simple_logic.c, simple_logic.o: A program with user input and logic for analysis.
- simple_logic_hack.o: The modified version after changing program logic.

## Tools & Resources

### Recommended Tools

#### Disassembly & Decompilation
- Ghidra - Open-source reverse engineering tool. (https://ghidra-sre.org/)
- IDA Free - Interactive disassembler. (https://hex-rays.com/ida-free/)

#### Binary Analysis
- strings - Extract readable text from a binary file.
- objdump - View assembly code from an executable.
- hexdump, xxd - View and manipulate binary file contents.
- file - Identify file types.
- binwalk - Analyze binary files for hidden data.

#### Hex Editing
- HexEd.it - Online hex editor. (https://hexed.it/)

#### Ghidra Scripting
- SavePatch.py - Save modified binaries in Ghidra. (https://github.com/schlafwandler/ghidra_SavePatch/blob/master/SavePatch.py)

## Running GCC on Windows

Since Windows doesn’t natively support GCC, you can compile the files using:

- **Windows Subsystem for Linux (WSL)**
  - Install WSL and Ubuntu:
    wsl --install -d Ubuntu
    sudo apt update && sudo apt install gcc

- **Virtual Machine**
  - Use VirtualBox (https://www.virtualbox.org/) or VMware (https://www.vmware.com/) with a Linux distribution.

- **Docker**
  - Install Docker (https://www.docker.com/) and run:
    docker run --rm -it gcc bash

## Steps to Follow

1. **Compile the Example Code**  
On Linux/macOS/WSL, run:  
gcc -o hello hello.c  
gcc -o simple_logic simple_logic.c  

2. **Analyze the Executable**  
View embedded strings:  
strings hello  
Disassemble the binary:  
objdump -d hello  

3. **Open in Ghidra**  
- Open Ghidra and create a new project.  
- Import the hello or simple_logic binary.  
- Run auto-analysis.  
- Navigate to "Defined Strings" (Ctrl + Shift + E).

4. **Modify a String in Ghidra**  
- Locate the string in the Defined Strings window.  
- Right-click the string and choose "Patch Data".  
- Enter a new string (must fit the existing space).

5. **Modify Program Logic (Change JNZ to JZ)**  
- Locate a CMP (compare) instruction followed by JNZ (Jump If Not Zero).  
- Right-click JNZ, select "Patch Instruction", and change it to JZ (Jump If Zero).

6. **Save Changes in Ghidra using SavePatch**  
   a. **Enable Ghidra scripting:**  
      - Go to Window → Script Manager.  
      - Right-click → New Script → Select Jython.
   
   b. **Paste and run the SavePatch script:**  
from ghidra.program.model.mem import MemoryAccessException  
from ghidra.program.model.symbol import SymbolUtilities  
from ghidra.program.model.lang import Register  
from ghidra.program.model.data import DataType  
from ghidra.app.script import GhidraScript  

# Set address of modified bytes  
start_of_patch = 0x10119c  # Replace with actual modified address  
patch_size = 16  # Adjust based on modifications  

# Write patch  
mem = currentProgram.getMemory()  
try:  
    mem.getBytes(toAddr(start_of_patch), patch_size)  
except MemoryAccessException:  
    print("Error accessing memory")
</div>
   c. **Save the modified binary:**  
      - Click Script Manager → Run SavePatch script.  
      - Export the modified file (hello_hack.o or simple_logic_hack.o).

7. **Run the Modified Binary**  
./hello_hack  
./simple_logic_hack  

## Conclusion

This repository provides a step-by-step guide for reverse engineering, covering:
- Basic binary analysis (strings, opcodes, disassembly)
- Using tools like Ghidra, objdump, and hexdump
- Modifying strings and logic in compiled binaries
- Saving patched executables with Ghidra

Happy hacking! 🚀
