## Mycroft's Type Reconstruction

Given Program:

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


### Step 1

Program flow (as per the SLOC number; please use any code editor to preview it nicely)

```
                phi(rdi__0,rdi__1)     phi(rdi__0,rdi__1)
                    [ ] -> [1d,1f]->e  [ ] -> [20,25] -> e
   phi(rdi__0,rdi__1)|T                 |T
s -> [ ] -> [4] -> <7> ---F---> [9] -> <b> -F-> <d> --F--> [d,13]
      |                                          |T           |
      |<------------------ [17,1b] <-F- <15> <- [ ]           |
      |                                  |T phi(rdi__0,rdi__1)|
      |<------------------------------------------------------|
```

Note: `rdi` register is predominant and will remain live in every section (4, 15, 1d, and 20).


### Step 2

Let's get rid of extraneous addresses and endbr64 instruction (which is not needed for the analysis)

```
4:  test    rdi,rdi     ; AND operation, but the results of the operation are not saved
    je      0x1d
    cmp     DWORD PTR [rdi],esi
    je      0x20
    jbe     0x15
    mov     rdi,QWORD PTR [rdi+0x8]
    jmp     0x4
15: jae     0x4
    mov     rdi,QWORD PTR [rdi+0x10]
    jmp     0x4
1d: xor     eax,eax     ; clearing the register
    ret    
20: mov     eax,0x1
    ret
```


### Step 3

We can now add the phi functions -

```
4   mov     rdi,phi(rdi__0,rdi__1)  ; added instruction
    test    rdi,rdi
    je      0x1d
    cmp     DWORD PTR [rdi],esi
    je      0x20
    jbe     0x15
    mov     rdi,QWORD PTR [rdi+0x8]
    jmp     0x4
15: mov     rdi,phi(rdi__0,rdi__1)  ; added instruction
    jae     0x4
    mov     rdi,QWORD PTR [rdi+0x10]
    jmp     0x4
1d: mov     rdi,phi(rdi__0,rdi__1)  ; added instruction
    xor     eax,eax
    ret    
20: mov     rdi,phi(rdi__0,rdi__1)  ; added instruction
    mov     eax,0x1
    ret
```


### Step 4

It's time to convert the program into Single Static Assignment (SSA)

- Use `/d`, `/w`, and `/b` for double-word (32-bit), word (16-bit), and byte (8-bit) sections of the registers. 

```
4   mov     rdi,phi(rdi__0,rdi__1)
    test    rdi,rdi
    je      0x1d
    cmp     DWORD PTR [rdi],rsi/d
    je      0x20
    jbe     0x15
    mov     rdi,QWORD PTR [rdi+0x8]
    jmp     0x4
15: mov     rdi,phi(rdi__0,rdi__1)
    jae     0x4
    mov     rdi,QWORD PTR [rdi+0x10]
    jmp     0x4
1d: mov     rdi,phi(rdi__0,rdi__1)
    xor     rax/d,rax/d
    ret    
20: mov     rdi,phi(rdi__0,rdi__1)
    mov     rax/d,0x1
    ret
```

- Append numbers. The initial values of registers are `rbp1`, `rsp1`, etc. Doing this helps avoid a mistake where we gorget to convert something.

```
4   mov     rdi2,phi(rdi1,rdi5)
    test    rdi2,rdi2
    je      0x1d
    cmp     DWORD PTR [rdi3],rsi1/d
    je      0x20
    jbe     0x15
    mov     rdi7,QWORD PTR [rdi6+0x8]
    jmp     0x4
15: mov     rdi5,phi(rdi4,rdi7)
    jae     0x4
    mov     rdi6,QWORD PTR [rdi5+0x10]
    jmp     0x4
1d: mov     rdi3,phi(rdi2,rdi7)
    xor     rax2/d,rax1/d
    ret    
20: mov     rdi4,phi(rdi3,rdi7)
    mov     rax3/d,0x1
    ret
```

Note:
- The program returns the value in either `rax2/d` or `rax3/d`.
- The argument of the program is in `rdi1`
- The function signature is
`f: T(rdi1) -> T(rax2/d) OR T(rax3/d)`


### Step 5

Perform Mycroft's Type Reconstruction

```
4   mov     rdi2,phi(rdi1,rdi5)         ; T(rdi2) = T(rdi1) = T(rdi6) = ptr(a)
    test    rdi2,rdi2                   ; T(rdi2) = ptr(a)
    je      0x1d
    cmp     DWORD PTR [rdi3],rsi1/d     ; T(rdi3) = T(rsi1/d) = ptr(a)
    je      0x20
    jbe     0x15
    mov     rdi7,QWORD PTR [rdi6+0x8]   ; T(rdi6) = ptr(T(rdi7)@8)
    jmp     0x4
15: mov     rdi5,phi(rdi4,rdi7)         ; T(rdi5) = T(rdi4) = T(rdi7) = ptr(a)
    jae     0x4
    mov     rdi6,QWORD PTR [rdi5+0x10]  ; T(rdi5) = ptr(T(rdi6)@10)
    jmp     0x4
1d: mov     rdi3,phi(rdi2,rdi7)         ; T(rdi3) = T(rdi2) = T(rdi7) = ptr(a)
    xor     rax2/d,rax1/d               ; T(rax2/d) = T(rax1/d) = int32_t
    ret    
20: mov     rdi4,phi(rdi3,rdi7)         ; T(rdi4) = T(rdi3) = T(rdi7) = ptr(a)
    mov     rax3/d,0x1                  ; T(rax3/d) = int32_t
    ret
```

Note:
- According to Mycroft's paper, rax register for this case will be an integer because of this instruction right here. Not a pointer because of 32 bits size!
- `rdi` register is a pointer in this example, and the value of the pointers are same: `a = b`.


We get the following from the above step

```
i.      TT(rdi1) = T(rdi2) = T(rdi3) = T(rdi4) = T(rdi5) = T(rdi6) = T(rdi7) = ptr(a)
ii.     T(rdi5) = ptr(T(rdi6)@10)
iii.    T(rdi6) = ptr(T(rdi7)@8)
```

from (i), (ii) & (iii) can be derived to -
```
        T(rdi6) = T(rdi5) = ptr(T(rdi6)@10) -> Fails occurs check
        T(rdi7) = T(rdi6) = ptr(T(rdi7)@8)  -> Fails occurs check
        T(rdi5) = T(rdi6) = prt(a)
```

Therefore the solution is:
```
        T(rdi5) = ptr(T(rdi6)@10)
                = ptr(ptr(a))
                = ptr(struct X)
                = T(rdi6)

        struct X {struct X *;}
```

Now, the final version is as follows -

```
4   mov     rdi2,phi(rdi1,rdi5)         ; T(rdi2) = T(rdi1) = T(rdi6) = struct X *
    test    rdi2,rdi2                   ; T(rdi2) = struct X *
    je      0x1d
    cmp     DWORD PTR [rdi3],rsi1/d     ; T(rdi3) = T(rsi1/d) = struct X *
    je      0x20
    jbe     0x15
    mov     rdi7,QWORD PTR [rdi6+0x8]   ; T(rdi6) = ptr(struct X * @8)
    jmp     0x4
15: mov     rdi5,phi(rdi4,rdi7)         ; T(rdi5) = T(rdi4) = T(rdi7) = struct X *
    jae     0x4
    mov     rdi6,QWORD PTR [rdi5+0x10]  ; T(rdi5) = ptr(struct X * @10)
    jmp     0x4
1d: mov     rdi3,phi(rdi2,rdi7)         ; T(rdi3) = T(rdi2) = T(rdi7) = struct X *
    xor     rax2/d,rax1/d               ; T(rax2/d) = T(rax1/d) = int32_t
    ret    
20: mov     rdi4,phi(rdi3,rdi7)         ; T(rdi4) = T(rdi3) = T(rdi7) = struct X *
    mov     rax3/d,0x1                  ; T(rax3/d) = int32_t
    ret
```


#### Type Signature

All set, now it is time to figure out the function signature.
The only argument is rdi, and we have `T(rdi) = struct X *`
The return value is either either `rax1/d` or `rax2/d`, and we
have `T(rax2/d) = T(rax3/d) = int32_t`

Therefore, the type signature for the given program is -

```
f: T(rdi1) -> T(rax2/d) OR T(rax3/d)
int32_t     f(struct X * x)
```