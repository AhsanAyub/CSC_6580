; nasm -f elf64 div1.asm && ld -o div1 div1.o

	section .text
	global _start

_start:	mov rax, 16
	mov rdx, 15
	mov rbx, 16
	div rbx
	mov rdi, rax
	mov rax, 60
	syscall
	hlt

