; nasm -f elf64 sqrt_list.asm && gcc -static -o sqrt_list sqrt_list.o -lm

	global main
	extern printf
	extern strtod
	extern sqrt
	extern puts

	section .text
main:
	; Usual function boilerplate.  It's a good idea to include this even
	; if you don't plan to modify the stack.  You can always remove it
	; later.
	push rbp
	mov rbp, rsp

	; Save our arguments on the stack because we are going to call other
	; functions, and it is easier than trying to save rsi and edi every
	; time.
	;
	; We want to save edi (an int), and rsi (a quad word).  We really don't
	; need to save rdx (the environment pointer), so we won't.  We do want
	; to reserve space for a temporary value, so we will want 8 more bytes.
	;
	; The stack grows "backward" in memory.  That is, as you push items
	; the stack pointer is decreased.  So to reserve memory on the stack
	; we just subtract the space needed.  Additonally, it is a Good Idea
	; for the stack to be aligned on a 16-byte boundary.
	; 
	; Prior to the call, the stack was aligned.  Then the call pushed the
	; return address (8 bytes) on the stack, and the stack was not aligned.
	; Then we pushed rbp (8 bytes) and it was aligned again.  So we need to
	; reserve a multiple of 16 to make sure it is still aligned.  The least
	; multiple of 16 that is greater or equal to 20 is 32.
	; 
	; A strategy you sometimes see is to reserve what you need, then force
	; alignment.
	; 
	; sub rsp, 20
	; and rsp, -16
	sub rsp, 32		; Reserve space for edi and rsi and align.
	mov DWORD [rbp-4], edi	; Store edi in the reserved space.
	add rsi, 8		; Skip the program name.
	mov QWORD [rbp-12], rsi	; Store rsi in the reserved space.
	; Remember the stack grows backward, so if we stored at [rbp] we would
	; overwrite the old stack!  The first mov will put the four bytes of
	; edi in [rbp-4], [rbp-3], [rbp-2], and [rbp-1].

	mov rbx, QWORD [rbp-12]
loop:
	; See if we have hit the NULL pointer.  If so, stop.
	mov rdi, QWORD [rbx]	; The second argument is here.
	test rdi, rdi
	je good
	mov rsi, 0		; Second argument to strtod should be NULL.
	call strtod

	; Stash the returned floating point value, which will be in xmm0.
	movsd QWORD [rbp-20], xmm0

	; Let's call sqrt.  The first (and only) floating point value is
	; already in xmm0, so we are ready to call right now.
	call sqrt

	; We want to set up for the print statement.  We want the original
	; value in xmm0, and the square root in xmm1.
	movsd xmm1, xmm0
	movsd xmm0, QWORD [rbp-20]
	mov rdi, fmt
	mov eax, 2
	call printf

	; Move to the next argument.
	add rbx, 8

	; Go around the loop again.
	jmp loop

	; Usual function boilerplate.  It's a good idea to include this even
	; if you don't plan to modify the tack.  You can alawys remove it
	; later.  We'll use the leave instruction here, and return zero from
	; main to indicate success.
good:
	mov eax, 0
done:
	leave
	ret

	section .data
fmt:	db "sqrt(%f) = %f",10,0

