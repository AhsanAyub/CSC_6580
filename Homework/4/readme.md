## Entry Point Disassembly

Take the `find_branches.py` Python code and modify it to disassembly the code starting at the program's entry point. For this you will need Python 3, the Capstone library, and the pyELFtools library. Make sure all are installed.

Hints:
* The `disasm` method takes two arguments: an array of the `code` to disassemble, which you get from `section.data()`, and an `offset`. The offset is not the offset into the array at which disassembly starts, but is the virtual address of the first byte in the `data` you give it.
* You will need to do something to the `data` array when you pass it to `disasm` so that disassembly can start at the entry point.
* If you want the virtual addresses in your disassembly to be correct, make sure the `offset` argument is the correct virtual address of the first byte.
* Get the segment's header. Get the entry point from the ELF file's header.
* Finally, remember that the code segment has a base virtual address where it starts.

Please name your program `entry_point.py`. The output should be as follows for disassembling the `ls`executable on Ubuntu 19.10.


```
$ python3 entry_point.py `which ls`
/usr/bin/ls:
0x67d0: endbr64
0x67d4: xor     ebp, ebp
0x67d6: mov     r9, rdx
0x67d9: pop     rsi
0x67da: mov     rdx, rsp
0x67dd: and     rsp, 0xfffffffffffffff0
0x67e1: push    rax
0x67e2: push    rsp
0x67e3: lea     r8, [rip + 0x10d66]
0x67ea: lea     rcx, [rip + 0x10cef]
0x67f1: lea     rdi, [rip - 0x1a08]
0x67f8: call    qword ptr [rip + 0x1c7d2]
0x67fe: hlt
0x67ff: nop
0x6800: lea     rdi, [rip + 0x1ca61]
0x6807: lea     rax, [rip + 0x1ca5a]
0x680e: cmp     rax, rdi
0x6811: je      0x6828
0x6813: mov     rax, qword ptr [rip + 0x1c7ae]
...
0x1756d:        jmp     0x4ca0
Contains branches.
```
