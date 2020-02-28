## Basic Blocks

Modify your `entry_point.py` code (or start with the provided solution) to identify basic blocks. Call your program `basic_blocks.py`. Store the basic blocks and then, at the end, print them in order by address.

Accept a file name followed by a (possibly empty) series of hexadecimal addresses as command-line arguments and assume these are basic block leaders. If no addresses are given on the command line, add the entry point to the stack as a basic block leader.

Print the block leader address, the block disassembly indented two spaces, and the next address(es) after the block. If you don't know the addresses, print "unknown."

Your output for a single basic block should look like this.

```
$ python3 basic_blocks.py `which python3`
/usr/bin/python3:
block at: 0x5cff70
  endbr64
  xor ebp, ebp
  mov r9, rdx
  pop rsi
  mov rdx, rsp
  and rsp, 0xfffffffffffffff0
  push rax
  push rsp
  mov r8, 0x679500
  mov rcx, 0x679490
  mov rdi, 0x4cf960
  call qword ptr [rip + 0x26905a]
  hlt
next: unknown
```

See the attached `rad.py` for the "random access disassembler" code.