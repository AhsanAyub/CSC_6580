; nasm -f elf64 div2.asm && ld -o div2 div2.o

	section .text
	global _start

_start:	mov rax, 16
	mov rdx, 16
	mov rbx, 16
	div rbx
	mov rdi, rax
	mov rax, 60
	syscall
	hlt

