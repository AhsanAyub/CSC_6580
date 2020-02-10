; @Author: Md. Ahsan Ayub
; nasm -f elf64 addsub.asm && gcc -static -o addsub addsub.o

; This program uses the Linux sys_write system call. See the table located here:
; https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

  global main
  extern printf
  extern atoi
  extern puts

	section .text

main:

  ; Accessing user input as line arguments
  push r12
  push r13
  push r14

  cmp rdi, 3
  jne errorMessage          ; Exactly two arguments are required

  mov r12, rsi              ; argv
  mov rdi, [r12+16]         ; argv[2]
  call atoi                 ; The value of the argument is in eax
  mov r15, rax              ; Storing the second argument in R15
  xor rax, rax              ; clear eax

  mov rdi, [r12+8]          ; argv[1]
  call atoi                 ; The value of the argument is in eax
  mov rdi, rax              ; Storing the second argument in RDI
  xor rax, rax              ; clear eax

  pop r14
  pop r13
  pop r12

  ; Default routines provided by Dr. Prowell
  call write_binary_qword
	call write_endl
	mov rax, 0; The second argument is here.
	ret

errorMessage:
  mov rdi, errMsg
  call puts
  jmp done

write_binary_qword:
  push rbp
  mov rbp, rsp
  ; Store rdi on the stack.  At this point rdi is occupying
	; the following addresses: rbp-1 through rbp-8.
  push rdi
	mov rcx, 8

.top:
  ; Zero out rax.  While assigning to eax would zero the high
  ; bits of rax,ret assigning to ah or al will not.
  mov rax, errMsg
	; Get the next byte to print.  We have arranged to get them
	; in order from highest order to lowest (big endian).
	mov al, BYTE [rbp+rcx-9]
	; Save important data.
	push rcx
	push rax
	; Get high nybble and divide by four.
	and rax, 0xf0
	shr rax, 2
	mov rdi, 1
	lea rsi, [nyb + rax]
	mov rdx, 4
	mov rax, 1
	syscall
	call write_space
	; Restore the byte value.
	pop rax
	; Get low nybble and multiply by four.
	and rax, 0xf
	shl rax, 2
	mov rdi, 1
	lea rsi, [nyb + rax]
	mov rdx, 4
	mov rax, 1
	syscall
	call write_space
	; Restore the index.
	pop rcx
	loop .top
	leave
	ret

write_space:
	mov rdi, 1
	mov rsi, space
	mov rdx, 1
	mov rax, 1
	syscall
	ret

write_endl:
	mov rdi, 1
	mov rsi, endl
	mov rdx, 1
	mov rax, 1
	syscall
	ret

	section .data

done:
  pop r14
  pop r13
  pop r12
  ret

nyb	db "0000"
	db "0001"
	db "0010"
	db "0011"
	db "0100"
	db "0101"
	db "0110"
	db "0111"
	db "1000"
	db "1001"
	db "1010"
	db "1011"
	db "1100"
	db "1101"
	db "1110"
	db "1111"
space:	db " "
endl:	db 10
addMsg: db "Adding", 10
subMsg: db "Subtracting", 10
errMsg: db "Expected exactly two integer arguments.", 10
