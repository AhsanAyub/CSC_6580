## Static Single Assignment (SSA)

Put the following program in SSA form.

Append numbers. The initial values of registers are `rbp1`, `rsp1`, etc. Use `/d`, `/w`, and `/b` for double-word (32-bit), word (16-bit), and byte (8-bit) sections of the registers. So, you might write `rax7/d` for the seventh value stored in `eax`.

```
4012dd:   push  rbp
4012de:   mov   rbp,rsp
4012e1:   mov   ecx,0x10
4012e6:   push  r14
4012e8:   mov   r14,rdi
4012eb:   sub   rsp,0x10
4012ef:   mov   ebx,0x10
4012f4:   mov   rax,r14
4012f7:   xor   rdx,rdx
4012fa:   div   rbx
4012fd:   mov   r14,rax
401300:   mov   al,BYTE PTR [rdx+0x40407d]
401306:   mov   BYTE PTR [rsp+rcx*1],al
401309:   loop  4012ef
40130b:   mov   edi,0x1
401310:   lea   rsi,[rsp+0x1]
401315:   mov   edx,0x10
40131a:   mov   eax,0x1
40131f:   syscall 
401321:   pop   r14
401323:   leave  
401324:   ret
```

## Mycroft's Type Reconstruction

Apply Mycroft's type reconstruction algorithm to the code below.  What's in `rdi`?

Can you tell what this program is doing?

```
0000000000000000 <.text>:
    0:      endbr64 
    4:      test    rdi,rdi
    7:      je      0x1d
    9:      cmp     DWORD PTR [rdi],esi
    b:      je      0x20
    d:      jbe     0x15
    f:      mov     rdi,QWORD PTR [rdi+0x8]
    13:     jmp     0x4
    15:     jae     0x4
    17:     mov     rdi,QWORD PTR [rdi+0x10]
    1b:     jmp     0x4
    1d:     xor     eax,eax
    1f:     ret    
    20:     mov     eax,0x1
    25:     ret
```