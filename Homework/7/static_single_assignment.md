## Static Signle Assignment (SSA)

Given Program:

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

### Step 1

Let's get rid of extraneous addresses and initial stack alignment operations (first two instructions; as it was mentioned not needed in the lecture)

```
        mov   ecx,0x10    ; loop will iterate 16 times
        push  r14         ; pushing the value in the r14 register to the stack for further usuage later
        mov   r14,rdi
        sub   rsp,0x10
4012ef: mov   ebx,0x10
        mov   rax,r14
        xor   rdx,rdx     ; clearing rdx register for the div operation
        div   rbx         ; quotient is in rax, remainder is in rdx, and diving what's store in both registers with rbx
        mov   r14,rax     ; moving the quotient that fits into rax from div operation into r14 to do further operation using loop
        mov   al,BYTE PTR [rdx+0x40407d]
        mov   BYTE PTR [rsp+rcx*1],al
        loop  4012ef      ; decrements rcx by 1
        mov   edi,0x1
        lea   rsi,[rsp+0x1]
        mov   edx,0x10
        mov   eax,0x1     ; important for syscall operation in the next instruction
        syscall           ; this clobbers rcx and r11 as well as the rax return value, but other registers are preserved
        pop   r14         ; all the opration above is done through the usage of r14 register, now it's time to store back what was in it before
        ret
```

Note: As push / pop operation does not impact the major oprations of the code, I think, we can exclude both instruction from our assessment. Thus, the final code before we perform program flow is as follows

```
        mov   ecx,0x10
        mov   r14,rdi
        sub   rsp,0x10
4012ef: mov   ebx,0x10
        mov   rax,r14
        xor   rdx,rdx
        div   rbx
        mov   r14,rax
        mov   al,BYTE PTR [rdx+0x40407d]
        mov   BYTE PTR [rsp+rcx*1],al
        loop  4012ef
        mov   edi,0x1
        lea   rsi,[rsp+0x1]
        mov   edx,0x10
        mov   eax,0x1
        syscall
        ret
```


### Step 2

Program flow (as per the SLOC number; please use any code editor to preview it nicely)

```
s -> [50,51,52] -> [ ] -> [53,54,55,56,57,58,59] -> <60> --false--> [61,62,63,64,65,66] -> e
                    |                                |
                    |<---------true------------------|
                            phi(r14_0, r14_1)
                            phi(rcx0, rcx1)
                            phi(rsp0, rsp1)
```                            

Note:
- `r14`, `rcx`, and `rsp` registers values will remain live after we come back to the join point
- `rax`, `rbx` and `rdx` registers I think will not necessarily be considered live as its values will be reinitialized in each iteration


### Step 3

We can now add the phi functions -

```
        mov   ecx,0x10
        mov   r14,rdi
        sub   rsp,0x10
4012ef: mov   r14, phi(r14__0, r14__1)        ; added instruction
        mov   rcx, phi(rcx__0, rcx__1)        ; added instruction
        mov   rsp, phi(rsp__0, rsp__1)        ; added instruction
        mov   ebx,0x10
        mov   rax,r14
        xor   rdx,rdx
        div   rbx
        mov   r14,rax
        mov   al,BYTE PTR [rdx+0x40407d]
        mov   BYTE PTR [rsp+rcx*1],al
        loop  4012ef
        mov   edi,0x1
        lea   rsi,[rsp+0x1]
        mov   edx,0x10
        mov   eax,0x1
        syscall
        ret
```


### Step 4

It's time to convert the program into Single Static Assignment (SSA)

- Use `/d`, `/w`, and `/b` for double-word (32-bit), word (16-bit), and byte (8-bit) sections of the registers.  

```
        mov   rcx/d,0x10
        mov   r14,rdi
        sub   rsp,0x10
4012ef: mov   r14, phi(r14__0, r14__1)        ; added instruction
        mov   rcx, phi(rcx__0, rcx__1)        ; added instruction
        mov   rsp, phi(rsp__0, rsp__1)        ; added instruction
        mov   rbx/d,0x10
        mov   rax,r14
        xor   rdx,rdx
        div   rbx
        mov   r14,rax
        mov   rax/b,BYTE PTR [rdx+0x40407d]
        mov   BYTE PTR [rsp+rcx*1],rax/b
        loop  4012ef
        mov   rdi/d,0x1
        lea   rsi,[rsp+0x1]
        mov   rdx/d,0x10
        mov   rax/d,0x1
        syscall
        ret
```

- Append numbers. The initial values of registers are `rbp1`, `rsp1`, etc. Doing this helps avoid a mistake where we gorget to convert something. The following is the final form of SSA -

```
        mov   rcx1/d,0x10
        mov   r14_1,rdi1
        sub   rsp1,0x10
4012ef: mov   r14_2, phi(r14_1, r14_3)
        mov   rcx2, phi(rcx1, rcx3)
        mov   rsp2, phi(rsp1, rsp3)
        mov   rbx1/d,0x10
        mov   rax1,r14_2
        xor   rdx2,rdx1
        div   rbx1
        mov   r14_3,rax2
        mov   rax3/b,BYTE PTR [rdx2+0x40407d]
        mov   BYTE PTR [rsp2+rcx2*1],rax3/b
        loop  4012ef
        mov   rdi2/d,0x1
        lea   rsi1,[rsp3+0x1]
        mov   rdx3/d,0x10
        mov   rax4/d,0x1
        syscall
        ret
```