	.file	"fakens.c"
	.section	.rodata
.LC0:
	.string	"A"
.LC1:
	.string	"NS"
.LC2:
	.string	"CNAME"
.LC3:
	.string	"SOA"
.LC4:
	.string	"PTR"
.LC5:
	.string	"MX"
.LC6:
	.string	"TXT"
.LC7:
	.string	"AAAA"
.LC8:
	.string	"SRV"
.LC9:
	.string	"TLSA"
	.data
	.align 64
	.type	type_list, @object
	.size	type_list, 176
type_list:
	.quad	.LC0
	.long	1
	.zero	4
	.quad	.LC1
	.long	2
	.zero	4
	.quad	.LC2
	.long	5
	.zero	4
	.quad	.LC3
	.long	6
	.zero	4
	.quad	.LC4
	.long	12
	.zero	4
	.quad	.LC5
	.long	15
	.zero	4
	.quad	.LC6
	.long	16
	.zero	4
	.quad	.LC7
	.long	28
	.zero	4
	.quad	.LC8
	.long	33
	.zero	4
	.quad	.LC9
	.long	52
	.zero	4
	.quad	0
	.long	0
	.zero	4
	.text
	.type	fcopystring, @function
fcopystring:
.LFB2:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$496, %rsp
	movq	%rsi, -168(%rbp)
	movq	%rdx, -160(%rbp)
	movq	%rcx, -152(%rbp)
	movq	%r8, -144(%rbp)
	movq	%r9, -136(%rbp)
	testb	%al, %al
	je	.L2
	movaps	%xmm0, -128(%rbp)
	movaps	%xmm1, -112(%rbp)
	movaps	%xmm2, -96(%rbp)
	movaps	%xmm3, -80(%rbp)
	movaps	%xmm4, -64(%rbp)
	movaps	%xmm5, -48(%rbp)
	movaps	%xmm6, -32(%rbp)
	movaps	%xmm7, -16(%rbp)
.L2:
	movq	%rdi, -488(%rbp)
	movl	$8, -472(%rbp)
	movl	$48, -468(%rbp)
	leaq	16(%rbp), %rax
	movq	%rax, -464(%rbp)
	leaq	-176(%rbp), %rax
	movq	%rax, -456(%rbp)
	leaq	-472(%rbp), %rdx
	movq	-488(%rbp), %rcx
	leaq	-448(%rbp), %rax
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	vsprintf
	leaq	-448(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	addl	$1, %eax
	cltq
	movq	%rax, %rdi
	call	malloc
	movq	%rax, -184(%rbp)
	leaq	-448(%rbp), %rdx
	movq	-184(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	strcpy
	movq	-184(%rbp), %rax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2:
	.size	fcopystring, .-fcopystring
	.type	packname, @function
packname:
.LFB3:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -24(%rbp)
	movq	%rsi, -32(%rbp)
	jmp	.L5
.L11:
	movq	-24(%rbp), %rax
	movq	%rax, -8(%rbp)
	jmp	.L6
.L8:
	addq	$1, -8(%rbp)
.L6:
	movq	-8(%rbp), %rax
	movzbl	(%rax), %eax
	testb	%al, %al
	je	.L7
	movq	-8(%rbp), %rax
	movzbl	(%rax), %eax
	cmpb	$46, %al
	jne	.L8
.L7:
	movq	-32(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -32(%rbp)
	movq	-8(%rbp), %rcx
	movq	-24(%rbp), %rdx
	subq	%rdx, %rcx
	movq	%rcx, %rdx
	movb	%dl, (%rax)
	movq	-8(%rbp), %rdx
	movq	-24(%rbp), %rax
	subq	%rax, %rdx
	movq	%rdx, %rax
	movq	%rax, %rdx
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rax
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	memmove
	movq	-8(%rbp), %rdx
	movq	-24(%rbp), %rax
	subq	%rax, %rdx
	movq	%rdx, %rax
	addq	%rax, -32(%rbp)
	movq	-8(%rbp), %rax
	movzbl	(%rax), %eax
	testb	%al, %al
	je	.L9
	movq	-8(%rbp), %rax
	addq	$1, %rax
	jmp	.L10
.L9:
	movq	-8(%rbp), %rax
.L10:
	movq	%rax, -24(%rbp)
.L5:
	movq	-24(%rbp), %rax
	movzbl	(%rax), %eax
	testb	%al, %al
	jne	.L11
	movq	-32(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -32(%rbp)
	movb	$0, (%rax)
	movq	-32(%rbp), %rax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3:
	.size	packname, .-packname
	.globl	bytefield
	.type	bytefield, @function
bytefield:
.LFB4:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -24(%rbp)
	movq	%rsi, -32(%rbp)
	movl	$0, -4(%rbp)
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -16(%rbp)
	jmp	.L14
.L15:
	movl	-4(%rbp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	addl	%eax, %eax
	movl	%eax, %ecx
	movq	-16(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -16(%rbp)
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addl	%ecx, %eax
	subl	$48, %eax
	movl	%eax, -4(%rbp)
.L14:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-16(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$2048, %eax
	testl	%eax, %eax
	jne	.L15
	jmp	.L16
.L17:
	addq	$1, -16(%rbp)
.L16:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-16(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L17
	movq	-24(%rbp), %rax
	movq	-16(%rbp), %rdx
	movq	%rdx, (%rax)
	movq	-32(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -32(%rbp)
	movl	-4(%rbp), %edx
	movb	%dl, (%rax)
	movq	-32(%rbp), %rax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE4:
	.size	bytefield, .-bytefield
	.globl	shortfield
	.type	shortfield, @function
shortfield:
.LFB5:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -24(%rbp)
	movq	%rsi, -32(%rbp)
	movl	$0, -4(%rbp)
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -16(%rbp)
	jmp	.L20
.L21:
	movl	-4(%rbp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	addl	%eax, %eax
	movl	%eax, %ecx
	movq	-16(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -16(%rbp)
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addl	%ecx, %eax
	subl	$48, %eax
	movl	%eax, -4(%rbp)
.L20:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-16(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$2048, %eax
	testl	%eax, %eax
	jne	.L21
	jmp	.L22
.L23:
	addq	$1, -16(%rbp)
.L22:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-16(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L23
	movq	-24(%rbp), %rax
	movq	-16(%rbp), %rdx
	movq	%rdx, (%rax)
	movq	-32(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -32(%rbp)
	movl	-4(%rbp), %edx
	shrl	$8, %edx
	movb	%dl, (%rax)
	movq	-32(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -32(%rbp)
	movl	-4(%rbp), %edx
	movb	%dl, (%rax)
	movq	-32(%rbp), %rax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	shortfield, .-shortfield
	.globl	longfield
	.type	longfield, @function
longfield:
.LFB6:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -24(%rbp)
	movq	%rsi, -32(%rbp)
	movq	$0, -8(%rbp)
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -16(%rbp)
	jmp	.L26
.L27:
	movq	-8(%rbp), %rdx
	movq	%rdx, %rax
	salq	$2, %rax
	addq	%rdx, %rax
	addq	%rax, %rax
	movq	%rax, %rcx
	movq	-16(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -16(%rbp)
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rcx, %rax
	subq	$48, %rax
	movq	%rax, -8(%rbp)
.L26:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-16(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$2048, %eax
	testl	%eax, %eax
	jne	.L27
	jmp	.L28
.L29:
	addq	$1, -16(%rbp)
.L28:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-16(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L29
	movq	-24(%rbp), %rax
	movq	-16(%rbp), %rdx
	movq	%rdx, (%rax)
	movq	-32(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -32(%rbp)
	movq	-8(%rbp), %rdx
	shrq	$24, %rdx
	movb	%dl, (%rax)
	movq	-32(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -32(%rbp)
	movq	-8(%rbp), %rdx
	shrq	$16, %rdx
	movb	%dl, (%rax)
	movq	-32(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -32(%rbp)
	movq	-8(%rbp), %rdx
	shrq	$8, %rdx
	movb	%dl, (%rax)
	movq	-32(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -32(%rbp)
	movq	-8(%rbp), %rdx
	movb	%dl, (%rax)
	movq	-32(%rbp), %rax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	longfield, .-longfield
	.type	milliwait, @function
milliwait:
.LFB7:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$272, %rsp
	movq	%rdi, -264(%rbp)
	movq	-264(%rbp), %rax
	movq	24(%rax), %rax
	cmpq	$99, %rax
	jg	.L32
	movq	-264(%rbp), %rax
	movq	16(%rax), %rax
	testq	%rax, %rax
	je	.L31
.L32:
	leaq	-128(%rbp), %rax
	movq	%rax, %rdi
	call	sigemptyset
	leaq	-128(%rbp), %rax
	movl	$14, %esi
	movq	%rax, %rdi
	call	sigaddset
	leaq	-256(%rbp), %rdx
	leaq	-128(%rbp), %rax
	movq	%rax, %rsi
	movl	$0, %edi
	call	sigprocmask
	movq	-264(%rbp), %rax
	movl	$0, %edx
	movq	%rax, %rsi
	movl	$0, %edi
	call	setitimer
	leaq	-128(%rbp), %rax
	movq	%rax, %rdi
	call	sigfillset
	leaq	-128(%rbp), %rax
	movl	$14, %esi
	movq	%rax, %rdi
	call	sigdelset
	leaq	-128(%rbp), %rax
	movq	%rax, %rdi
	call	sigsuspend
	leaq	-256(%rbp), %rax
	movl	$0, %edx
	movq	%rax, %rsi
	movl	$2, %edi
	call	sigprocmask
.L31:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE7:
	.size	milliwait, .-milliwait
	.type	millisleep, @function
millisleep:
.LFB8:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$48, %rsp
	movl	%edi, -36(%rbp)
	movq	$0, -32(%rbp)
	movq	$0, -24(%rbp)
	movl	-36(%rbp), %ecx
	movl	$274877907, %edx
	movl	%ecx, %eax
	imull	%edx
	sarl	$6, %edx
	movl	%ecx, %eax
	sarl	$31, %eax
	subl	%eax, %edx
	movl	%edx, %eax
	cltq
	movq	%rax, -16(%rbp)
	movl	-36(%rbp), %ecx
	movl	$274877907, %edx
	movl	%ecx, %eax
	imull	%edx
	sarl	$6, %edx
	movl	%ecx, %eax
	sarl	$31, %eax
	subl	%eax, %edx
	movl	%edx, %eax
	imull	$1000, %eax, %eax
	subl	%eax, %ecx
	movl	%ecx, %eax
	imull	$1000, %eax, %eax
	cltq
	movq	%rax, -8(%rbp)
	leaq	-32(%rbp), %rax
	movq	%rax, %rdi
	call	milliwait
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE8:
	.size	millisleep, .-millisleep
	.section	.rodata
	.align 8
.LC10:
	.string	"fakens: unknown record type %s\n"
.LC11:
	.string	"PASS ON NOT FOUND"
.LC12:
	.string	"DNSSEC "
.LC13:
	.string	"AA "
.LC14:
	.string	"DELAY="
.LC15:
	.string	"TTL="
.LC16:
	.string	" "
.LC17:
	.string	"%s."
	.text
	.type	find_records, @function
find_records:
.LFB9:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%rbx
	subq	$952, %rsp
	.cfi_offset 3, -24
	movq	%rdi, -920(%rbp)
	movq	%rsi, -928(%rbp)
	movq	%rdx, -936(%rbp)
	movq	%rcx, -944(%rbp)
	movl	%r8d, -948(%rbp)
	movq	%r9, -960(%rbp)
	movl	$1, -20(%rbp)
	movq	-936(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	movl	%eax, -100(%rbp)
	movl	$0, -24(%rbp)
	movq	-960(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	movq	$type_list, -32(%rbp)
	jmp	.L36
.L39:
	movq	-32(%rbp), %rax
	movq	(%rax), %rax
	movq	-944(%rbp), %rdx
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	strcmp
	testl	%eax, %eax
	jne	.L37
	jmp	.L38
.L37:
	addq	$16, -32(%rbp)
.L36:
	movq	-32(%rbp), %rax
	movq	(%rax), %rax
	testq	%rax, %rax
	jne	.L39
.L38:
	movq	-32(%rbp), %rax
	movq	(%rax), %rax
	testq	%rax, %rax
	jne	.L40
	movq	stderr(%rip), %rax
	movq	-944(%rbp), %rdx
	movl	$.LC10, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	fprintf
	movl	$3, %eax
	jmp	.L124
.L40:
	movb	$0, -640(%rbp)
	movq	-920(%rbp), %rax
	movl	$0, %edx
	movl	$0, %esi
	movq	%rax, %rdi
	call	fseek
	cmpq	$0, 24(%rbp)
	je	.L42
	movq	24(%rbp), %rax
	movl	$1, (%rax)
.L42:
	cmpq	$0, 32(%rbp)
	je	.L43
	movq	32(%rbp), %rax
	movl	$1, (%rax)
.L43:
	jmp	.L44
.L120:
	movl	$0, -104(%rbp)
	movq	-32(%rbp), %rax
	movl	8(%rax), %eax
	movl	%eax, -60(%rbp)
	movl	-948(%rbp), %eax
	movl	%eax, -64(%rbp)
	movl	$0, -68(%rbp)
	movl	$0, -72(%rbp)
	movl	$0, -76(%rbp)
	movl	$3600, -80(%rbp)
	leaq	-384(%rbp), %rax
	movq	%rax, -904(%rbp)
	jmp	.L45
.L46:
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
.L45:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L46
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	testb	%al, %al
	je	.L47
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	cmpb	$59, %al
	jne	.L48
.L47:
	jmp	.L44
.L48:
	movq	-904(%rbp), %rax
	movl	$17, %edx
	movl	$.LC11, %esi
	movq	%rax, %rdi
	call	strncmp
	testl	%eax, %eax
	jne	.L50
	movl	$1, -24(%rbp)
	jmp	.L44
.L50:
	leaq	-384(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	cltq
	leaq	-384(%rbp), %rdx
	addq	%rdx, %rax
	movq	%rax, -48(%rbp)
	jmp	.L51
.L52:
	subq	$1, -48(%rbp)
.L51:
	call	__ctype_b_loc
	movq	(%rax), %rax
	movq	-48(%rbp), %rdx
	subq	$1, %rdx
	movzbl	(%rdx), %edx
	movzbl	%dl, %edx
	addq	%rdx, %rdx
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L52
	movq	-48(%rbp), %rax
	movb	$0, (%rax)
	leaq	-384(%rbp), %rax
	movq	%rax, -904(%rbp)
.L67:
	movq	-904(%rbp), %rax
	movl	$7, %edx
	movl	$.LC12, %esi
	movq	%rax, %rdi
	call	strncmp
	testl	%eax, %eax
	jne	.L53
	movl	$1, -68(%rbp)
	movq	-904(%rbp), %rax
	addq	$7, %rax
	movq	%rax, -904(%rbp)
	jmp	.L54
.L53:
	movq	-904(%rbp), %rax
	movl	$3, %edx
	movl	$.LC13, %esi
	movq	%rax, %rdi
	call	strncmp
	testl	%eax, %eax
	jne	.L55
	movl	$1, -72(%rbp)
	movq	-904(%rbp), %rax
	addq	$3, %rax
	movq	%rax, -904(%rbp)
	jmp	.L54
.L55:
	movq	-904(%rbp), %rax
	movl	$6, %edx
	movl	$.LC14, %esi
	movq	%rax, %rdi
	call	strncmp
	testl	%eax, %eax
	jne	.L56
	movq	-904(%rbp), %rax
	addq	$6, %rax
	movq	%rax, -904(%rbp)
	jmp	.L57
.L59:
	movl	-76(%rbp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	addl	%eax, %eax
	movl	%eax, %edx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addl	%edx, %eax
	subl	$48, %eax
	movl	%eax, -76(%rbp)
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
.L57:
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	cmpb	$47, %al
	jbe	.L58
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	cmpb	$57, %al
	jbe	.L59
.L58:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	je	.L54
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
	jmp	.L67
.L56:
	movq	-904(%rbp), %rax
	movl	$4, %edx
	movl	$.LC15, %esi
	movq	%rax, %rdi
	call	strncmp
	testl	%eax, %eax
	jne	.L61
	movl	$0, -80(%rbp)
	movq	-904(%rbp), %rax
	addq	$4, %rax
	movq	%rax, -904(%rbp)
	jmp	.L62
.L64:
	movl	-80(%rbp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	addl	%eax, %eax
	movl	%eax, %edx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addl	%edx, %eax
	subl	$48, %eax
	movl	%eax, -80(%rbp)
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
.L62:
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	cmpb	$47, %al
	jbe	.L63
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	cmpb	$57, %al
	jbe	.L64
.L63:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	je	.L54
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
	jmp	.L67
.L61:
	nop
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L68
	jmp	.L125
.L54:
	jmp	.L67
.L125:
	leaq	-640(%rbp), %rax
	movq	%rax, -88(%rbp)
	leaq	-896(%rbp), %rax
	movq	%rax, -96(%rbp)
	jmp	.L69
.L70:
	movq	-88(%rbp), %rbx
	leaq	1(%rbx), %rax
	movq	%rax, -88(%rbp)
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	movl	%eax, %edi
	call	tolower
	movb	%al, (%rbx)
	movq	-96(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -96(%rbp)
	movq	-904(%rbp), %rdx
	leaq	1(%rdx), %rcx
	movq	%rcx, -904(%rbp)
	movzbl	(%rdx), %edx
	movb	%dl, (%rax)
.L69:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	je	.L70
	movq	-88(%rbp), %rax
	subq	$1, %rax
	movzbl	(%rax), %eax
	cmpb	$46, %al
	je	.L71
	movq	-928(%rbp), %rdx
	movq	-88(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	strcpy
	movq	-928(%rbp), %rdx
	movq	-96(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	strcpy
	jmp	.L68
.L71:
	movq	-88(%rbp), %rax
	subq	$1, %rax
	movb	$0, (%rax)
	movq	-96(%rbp), %rax
	subq	$1, %rax
	movb	$0, (%rax)
.L68:
	movzbl	-640(%rbp), %eax
	cmpb	$42, %al
	jne	.L72
	leaq	-640(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	subl	$1, %eax
	movl	%eax, -108(%rbp)
	movl	-100(%rbp), %eax
	cmpl	-108(%rbp), %eax
	jle	.L73
	movl	-100(%rbp), %eax
	movslq	%eax, %rdx
	movl	-108(%rbp), %eax
	cltq
	subq	%rax, %rdx
	movq	-936(%rbp), %rax
	addq	%rdx, %rax
	leaq	-640(%rbp), %rdx
	addq	$1, %rdx
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	strcmp
	testl	%eax, %eax
	je	.L73
	jmp	.L44
.L73:
	jmp	.L74
.L72:
	leaq	-640(%rbp), %rdx
	movq	-936(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	strcmp
	testl	%eax, %eax
	je	.L74
	jmp	.L44
.L74:
	cmpl	$1, -20(%rbp)
	jne	.L75
	movl	$4, -20(%rbp)
.L75:
	jmp	.L76
.L77:
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
.L76:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L77
	movq	-904(%rbp), %rax
	movl	$5, %edx
	movl	$.LC2, %esi
	movq	%rax, %rdi
	call	strncmp
	testl	%eax, %eax
	jne	.L78
	movl	$5, -60(%rbp)
	movl	$5, -64(%rbp)
	movl	$1, -104(%rbp)
	jmp	.L79
.L78:
	movl	-948(%rbp), %eax
	movslq	%eax, %rdx
	movq	-904(%rbp), %rax
	movq	-944(%rbp), %rcx
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	strncmp
	testl	%eax, %eax
	jne	.L80
	call	__ctype_b_loc
	movq	(%rax), %rax
	movq	-904(%rbp), %rcx
	movl	-948(%rbp), %edx
	movslq	%edx, %rdx
	addq	%rcx, %rdx
	movzbl	(%rdx), %edx
	movzbl	%dl, %edx
	addq	%rdx, %rdx
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L79
.L80:
	jmp	.L44
.L79:
	cmpl	$0, -76(%rbp)
	je	.L81
	movl	-76(%rbp), %eax
	movl	%eax, %edi
	call	millisleep
.L81:
	cmpq	$0, 24(%rbp)
	je	.L82
	cmpl	$0, -68(%rbp)
	jne	.L82
	movq	24(%rbp), %rax
	movl	$0, (%rax)
.L82:
	cmpq	$0, 32(%rbp)
	je	.L83
	cmpl	$0, -72(%rbp)
	jne	.L83
	movq	32(%rbp), %rax
	movl	$0, (%rax)
.L83:
	movl	$0, -20(%rbp)
	movq	16(%rbp), %rax
	movl	(%rax), %eax
	leal	1(%rax), %edx
	movq	16(%rbp), %rax
	movl	%edx, (%rax)
	movq	-904(%rbp), %rdx
	movl	-64(%rbp), %eax
	cltq
	addq	%rdx, %rax
	movq	%rax, -904(%rbp)
	jmp	.L84
.L85:
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
.L84:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L85
	movzbl	-640(%rbp), %eax
	cmpb	$42, %al
	je	.L86
	leaq	-896(%rbp), %rax
	jmp	.L87
.L86:
	movq	-936(%rbp), %rax
.L87:
	movq	-40(%rbp), %rdx
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	packname
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movl	-60(%rbp), %edx
	sarl	$8, %edx
	movb	%dl, (%rax)
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movl	-60(%rbp), %edx
	movb	%dl, (%rax)
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movb	$0, (%rax)
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movb	$1, (%rax)
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movl	-80(%rbp), %edx
	shrl	$24, %edx
	movb	%dl, (%rax)
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movl	-80(%rbp), %edx
	shrl	$16, %edx
	movb	%dl, (%rax)
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movl	-80(%rbp), %edx
	shrl	$8, %edx
	movb	%dl, (%rax)
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movl	-80(%rbp), %edx
	movb	%dl, (%rax)
	movq	-40(%rbp), %rax
	movq	%rax, -120(%rbp)
	addq	$2, -40(%rbp)
	cmpl	$52, -60(%rbp)
	ja	.L88
	movl	-60(%rbp), %eax
	movq	.L90(,%rax,8), %rax
	jmp	*%rax
	.section	.rodata
	.align 8
	.align 4
.L90:
	.quad	.L88
	.quad	.L89
	.quad	.L91
	.quad	.L88
	.quad	.L88
	.quad	.L91
	.quad	.L92
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L91
	.quad	.L88
	.quad	.L88
	.quad	.L93
	.quad	.L94
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L95
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L96
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L88
	.quad	.L97
	.text
.L92:
	movq	-904(%rbp), %rax
	movl	$.LC16, %esi
	movq	%rax, %rdi
	call	strtok
	movq	%rax, -904(%rbp)
	movq	-904(%rbp), %rbx
	movq	-904(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	cltq
	addq	%rbx, %rax
	movq	%rax, -48(%rbp)
	movq	-48(%rbp), %rax
	subq	$1, %rax
	movzbl	(%rax), %eax
	cmpb	$46, %al
	je	.L98
	movq	-928(%rbp), %rdx
	movq	-48(%rbp), %rax
	movl	$.LC17, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	sprintf
.L98:
	movq	-904(%rbp), %rax
	movq	-40(%rbp), %rdx
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	packname
	movq	%rax, -40(%rbp)
	movl	$.LC16, %esi
	movl	$0, %edi
	call	strtok
	movq	%rax, -904(%rbp)
	movq	-904(%rbp), %rax
	movq	-40(%rbp), %rdx
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	packname
	movq	%rax, -40(%rbp)
	movq	-904(%rbp), %rbx
	movq	-904(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	cltq
	addq	%rbx, %rax
	movq	%rax, -904(%rbp)
	movq	-904(%rbp), %rax
	movb	$32, (%rax)
	jmp	.L99
.L100:
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
.L99:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L100
	movq	-40(%rbp), %rdx
	leaq	-904(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	longfield
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rdx
	leaq	-904(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	longfield
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rdx
	leaq	-904(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	longfield
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rdx
	leaq	-904(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	longfield
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rdx
	leaq	-904(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	longfield
	movq	%rax, -40(%rbp)
	jmp	.L88
.L89:
	movq	-904(%rbp), %rax
	movq	-40(%rbp), %rdx
	movq	%rax, %rsi
	movl	$2, %edi
	call	inet_pton
	addq	$4, -40(%rbp)
	jmp	.L88
.L95:
	movq	-904(%rbp), %rax
	movq	-40(%rbp), %rdx
	movq	%rax, %rsi
	movl	$10, %edi
	call	inet_pton
	addq	$16, -40(%rbp)
	jmp	.L88
.L93:
	movq	-40(%rbp), %rdx
	leaq	-904(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	shortfield
	movq	%rax, -40(%rbp)
	movq	-48(%rbp), %rax
	subq	$1, %rax
	movzbl	(%rax), %eax
	cmpb	$46, %al
	je	.L101
	movq	-928(%rbp), %rdx
	movq	-48(%rbp), %rax
	movl	$.LC17, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	sprintf
.L101:
	movq	-904(%rbp), %rax
	movq	-40(%rbp), %rdx
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	packname
	movq	%rax, -40(%rbp)
	jmp	.L88
.L94:
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movq	%rax, -128(%rbp)
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	cmpb	$34, %al
	jne	.L102
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
.L102:
	jmp	.L103
.L105:
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movq	-904(%rbp), %rdx
	leaq	1(%rdx), %rcx
	movq	%rcx, -904(%rbp)
	movzbl	(%rdx), %edx
	movb	%dl, (%rax)
.L103:
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	testb	%al, %al
	je	.L104
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	cmpb	$34, %al
	jne	.L105
.L104:
	movq	-40(%rbp), %rdx
	movq	-128(%rbp), %rax
	subq	%rax, %rdx
	movq	%rdx, %rax
	leal	-1(%rax), %edx
	movq	-128(%rbp), %rax
	movb	%dl, (%rax)
	jmp	.L88
.L97:
	movq	-40(%rbp), %rdx
	leaq	-904(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	bytefield
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rdx
	leaq	-904(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	bytefield
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rdx
	leaq	-904(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	bytefield
	movq	%rax, -40(%rbp)
	jmp	.L106
.L112:
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	movl	%eax, %edi
	call	toupper
	movl	%eax, %ebx
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$2048, %eax
	testl	%eax, %eax
	je	.L107
	movl	$48, %eax
	jmp	.L108
.L107:
	movl	$55, %eax
.L108:
	subl	%eax, %ebx
	movl	%ebx, %eax
	sall	$4, %eax
	movl	%eax, -56(%rbp)
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$4096, %eax
	testl	%eax, %eax
	je	.L109
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	movl	%eax, %edi
	call	toupper
	movl	%eax, %ebx
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$2048, %eax
	testl	%eax, %eax
	je	.L110
	movl	$48, %eax
	jmp	.L111
.L110:
	movl	$55, %eax
.L111:
	subl	%eax, %ebx
	movl	%ebx, %eax
	orl	%eax, -56(%rbp)
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
.L109:
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movl	-56(%rbp), %edx
	movb	%dl, (%rax)
.L106:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$4096, %eax
	testl	%eax, %eax
	jne	.L112
	jmp	.L88
.L96:
	movl	$0, -52(%rbp)
	jmp	.L113
.L118:
	movl	$0, -56(%rbp)
	jmp	.L114
.L115:
	movl	-56(%rbp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	addl	%eax, %eax
	movl	%eax, %ecx
	movq	-904(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -904(%rbp)
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addl	%ecx, %eax
	subl	$48, %eax
	movl	%eax, -56(%rbp)
.L114:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$2048, %eax
	testl	%eax, %eax
	jne	.L115
	jmp	.L116
.L117:
	movq	-904(%rbp), %rax
	addq	$1, %rax
	movq	%rax, -904(%rbp)
.L116:
	call	__ctype_b_loc
	movq	(%rax), %rdx
	movq	-904(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	addq	%rax, %rax
	addq	%rdx, %rax
	movzwl	(%rax), %eax
	movzwl	%ax, %eax
	andl	$8192, %eax
	testl	%eax, %eax
	jne	.L117
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movl	-56(%rbp), %edx
	sarl	$8, %edx
	movb	%dl, (%rax)
	movq	-40(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -40(%rbp)
	movl	-56(%rbp), %edx
	movb	%dl, (%rax)
	addl	$1, -52(%rbp)
.L113:
	cmpl	$2, -52(%rbp)
	jle	.L118
.L91:
	movq	-48(%rbp), %rax
	subq	$1, %rax
	movzbl	(%rax), %eax
	cmpb	$46, %al
	je	.L119
	movq	-928(%rbp), %rdx
	movq	-48(%rbp), %rax
	movl	$.LC17, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	sprintf
.L119:
	movq	-904(%rbp), %rax
	movq	-40(%rbp), %rdx
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	packname
	movq	%rax, -40(%rbp)
	nop
.L88:
	movq	-40(%rbp), %rdx
	movq	-120(%rbp), %rax
	subq	%rax, %rdx
	movq	%rdx, %rax
	subq	$2, %rax
	sarq	$8, %rax
	movl	%eax, %edx
	movq	-120(%rbp), %rax
	movb	%dl, (%rax)
	movq	-120(%rbp), %rax
	addq	$1, %rax
	movq	-40(%rbp), %rcx
	movq	-120(%rbp), %rdx
	subq	%rdx, %rcx
	movq	%rcx, %rdx
	subl	$2, %edx
	movb	%dl, (%rax)
.L44:
	movq	-920(%rbp), %rdx
	leaq	-384(%rbp), %rax
	movl	$256, %esi
	movq	%rax, %rdi
	call	fgets
	testq	%rax, %rax
	jne	.L120
	movq	-960(%rbp), %rax
	movq	-40(%rbp), %rdx
	movq	%rdx, (%rax)
	cmpl	$1, -20(%rbp)
	jne	.L121
	cmpl	$0, -24(%rbp)
	jne	.L122
.L121:
	movl	-20(%rbp), %eax
	jmp	.L123
.L122:
	movl	$5, %eax
.L123:
	nop
.L124:
	addq	$952, %rsp
	popq	%rbx
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE9:
	.size	find_records, .-find_records
	.type	alarmfn, @function
alarmfn:
.LFB10:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -4(%rbp)
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE10:
	.size	alarmfn, .-alarmfn
	.type	special_manyhome, @function
special_manyhome:
.LFB11:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$48, %rsp
	movq	%rdi, -40(%rbp)
	movq	%rsi, -48(%rbp)
	movq	-40(%rbp), %rax
	addq	$12, %rax
	movq	%rax, -8(%rbp)
	movq	-40(%rbp), %rax
	movl	$12, %edx
	movl	$0, %esi
	movq	%rax, %rdi
	call	memset
	movl	$104, -12(%rbp)
	jmp	.L128
.L131:
	movl	$0, -16(%rbp)
	jmp	.L129
.L130:
	movq	-8(%rbp), %rdx
	movq	-48(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	packname
	movq	%rax, -8(%rbp)
	movq	-8(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -8(%rbp)
	movb	$0, (%rax)
	movq	-8(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -8(%rbp)
	movb	$1, (%rax)
	movq	-8(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -8(%rbp)
	movb	$0, (%rax)
	movq	-8(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -8(%rbp)
	movb	$1, (%rax)
	addq	$4, -8(%rbp)
	movq	-8(%rbp), %rax
	movq	%rax, -24(%rbp)
	addq	$2, -8(%rbp)
	movq	-8(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -8(%rbp)
	movb	$10, (%rax)
	movq	-8(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -8(%rbp)
	movb	$-6, (%rax)
	movq	-8(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -8(%rbp)
	movl	-12(%rbp), %edx
	movb	%dl, (%rax)
	movq	-8(%rbp), %rax
	leaq	1(%rax), %rdx
	movq	%rdx, -8(%rbp)
	movl	-16(%rbp), %edx
	movb	%dl, (%rax)
	movq	-8(%rbp), %rdx
	movq	-24(%rbp), %rax
	subq	%rax, %rdx
	movq	%rdx, %rax
	subq	$2, %rax
	sarq	$8, %rax
	movl	%eax, %edx
	movq	-24(%rbp), %rax
	movb	%dl, (%rax)
	movq	-24(%rbp), %rax
	addq	$1, %rax
	movq	-8(%rbp), %rcx
	movq	-24(%rbp), %rdx
	subq	%rdx, %rcx
	movq	%rcx, %rdx
	subl	$2, %edx
	movb	%dl, (%rax)
	addl	$1, -16(%rbp)
.L129:
	cmpl	$255, -16(%rbp)
	jle	.L130
	addl	$1, -12(%rbp)
.L128:
	cmpl	$111, -12(%rbp)
	jle	.L131
	movq	-40(%rbp), %rax
	addq	$6, %rax
	movb	$8, (%rax)
	movq	-40(%rbp), %rax
	addq	$7, %rax
	movb	$0, (%rax)
	movq	-40(%rbp), %rax
	addq	$10, %rax
	movb	$0, (%rax)
	movq	-40(%rbp), %rax
	addq	$11, %rax
	movb	$0, (%rax)
	movq	stdout(%rip), %rdx
	movq	-8(%rbp), %rcx
	movq	-40(%rbp), %rax
	subq	%rax, %rcx
	movq	%rcx, %rax
	movq	%rax, %rsi
	movq	-40(%rbp), %rax
	movq	%rdx, %rcx
	movq	%rsi, %rdx
	movl	$1, %esi
	movq	%rax, %rdi
	call	fwrite
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE11:
	.size	special_manyhome, .-special_manyhome
	.type	special_again, @function
special_again:
.LFB12:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -24(%rbp)
	movq	%rsi, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	%rax, %rdi
	call	atoi
	movl	%eax, -4(%rbp)
	cmpl	$0, -4(%rbp)
	jle	.L134
	movl	-4(%rbp), %eax
	movl	%eax, %edi
	call	sleep
.L134:
	movl	$2, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE12:
	.size	special_again, .-special_again
	.section	.rodata
	.align 8
.LC18:
	.string	"fakens: expected 3 arguments, received %d\n"
.LC19:
	.string	"%s/dnszones"
	.align 8
.LC20:
	.string	"fakens: failed to opendir %s: %s\n"
.LC21:
	.string	"qualify."
.LC22:
	.string	"%s"
.LC23:
	.string	"db."
.LC24:
	.string	"ip4."
.LC25:
	.string	"%s.in-addr.arpa"
.LC26:
	.string	"ip6."
.LC27:
	.string	"%s.ip6.arpa"
.LC28:
	.string	"manyhome.test.ex"
.LC29:
	.string	"test.again.dns"
.LC30:
	.string	"test.fail.dns"
.LC31:
	.string	"dontqualify"
	.align 8
.LC32:
	.string	"fakens: query not in faked zone: domain is: %s\n"
.LC33:
	.string	"%s/dnszones/%s"
.LC34:
	.string	"r"
	.align 8
.LC35:
	.string	"fakens: failed to open %s: %s\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB13:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%rbx
	subq	$66760, %rsp
	.cfi_offset 3, -24
	movl	%edi, -66756(%rbp)
	movq	%rsi, -66768(%rbp)
	movl	$0, -28(%rbp)
	movq	$0, -40(%rbp)
	movq	$0, -64(%rbp)
	leaq	-66736(%rbp), %rax
	movq	%rax, -72(%rbp)
	leaq	-66736(%rbp), %rax
	movq	%rax, -66744(%rbp)
	movl	$alarmfn, %esi
	movl	$14, %edi
	call	signal
	cmpl	$4, -66756(%rbp)
	je	.L137
	movl	-66756(%rbp), %eax
	leal	-1(%rax), %edx
	movq	stderr(%rip), %rax
	movl	$.LC18, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	fprintf
	movl	$3, %eax
	jmp	.L169
.L137:
	movq	-66768(%rbp), %rax
	addq	$8, %rax
	movq	(%rax), %rdx
	leaq	-1152(%rbp), %rax
	movl	$.LC19, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	sprintf
	leaq	-1152(%rbp), %rax
	movq	%rax, %rdi
	call	opendir
	movq	%rax, -80(%rbp)
	cmpq	$0, -80(%rbp)
	jne	.L139
	call	__errno_location
	movl	(%rax), %eax
	movl	%eax, %edi
	call	strerror
	movq	%rax, %rcx
	movq	stderr(%rip), %rax
	leaq	-1152(%rbp), %rdx
	movl	$.LC20, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	fprintf
	movl	$3, %eax
	jmp	.L169
.L139:
	jmp	.L140
.L146:
	movq	-88(%rbp), %rax
	addq	$19, %rax
	movq	%rax, -96(%rbp)
	movq	-96(%rbp), %rax
	movl	$8, %edx
	movl	$.LC21, %esi
	movq	%rax, %rdi
	call	strncmp
	testl	%eax, %eax
	jne	.L141
	movq	-96(%rbp), %rax
	addq	$7, %rax
	movq	%rax, %rsi
	movl	$.LC22, %edi
	movl	$0, %eax
	call	fcopystring
	movq	%rax, -40(%rbp)
	jmp	.L140
.L141:
	movq	-96(%rbp), %rax
	movl	$3, %edx
	movl	$.LC23, %esi
	movq	%rax, %rdi
	call	strncmp
	testl	%eax, %eax
	je	.L142
	jmp	.L140
.L142:
	movq	-96(%rbp), %rax
	addq	$3, %rax
	movl	$4, %edx
	movl	$.LC24, %esi
	movq	%rax, %rdi
	call	strncmp
	testl	%eax, %eax
	jne	.L143
	movq	-96(%rbp), %rax
	addq	$6, %rax
	movq	%rax, %rsi
	movl	$.LC25, %edi
	movl	$0, %eax
	call	fcopystring
	movq	%rax, %rdx
	movl	-28(%rbp), %eax
	cltq
	salq	$4, %rax
	leaq	-16(%rbp), %rbx
	addq	%rbx, %rax
	subq	$624, %rax
	movq	%rdx, (%rax)
	jmp	.L144
.L143:
	movq	-96(%rbp), %rax
	addq	$3, %rax
	movl	$4, %edx
	movl	$.LC26, %esi
	movq	%rax, %rdi
	call	strncmp
	testl	%eax, %eax
	jne	.L145
	movq	-96(%rbp), %rax
	addq	$6, %rax
	movq	%rax, %rsi
	movl	$.LC27, %edi
	movl	$0, %eax
	call	fcopystring
	movq	%rax, %rdx
	movl	-28(%rbp), %eax
	cltq
	salq	$4, %rax
	leaq	-16(%rbp), %rbx
	addq	%rbx, %rax
	subq	$624, %rax
	movq	%rdx, (%rax)
	jmp	.L144
.L145:
	movq	-96(%rbp), %rax
	addq	$2, %rax
	movq	%rax, %rsi
	movl	$.LC22, %edi
	movl	$0, %eax
	call	fcopystring
	movq	%rax, %rdx
	movl	-28(%rbp), %eax
	cltq
	salq	$4, %rax
	leaq	-16(%rbp), %rbx
	addq	%rbx, %rax
	subq	$624, %rax
	movq	%rdx, (%rax)
.L144:
	movl	-28(%rbp), %ebx
	leal	1(%rbx), %eax
	movl	%eax, -28(%rbp)
	movq	-96(%rbp), %rax
	movq	%rax, %rsi
	movl	$.LC22, %edi
	movl	$0, %eax
	call	fcopystring
	movq	%rax, %rdx
	movslq	%ebx, %rax
	salq	$4, %rax
	leaq	-16(%rbp), %rbx
	addq	%rbx, %rax
	subq	$624, %rax
	movq	%rdx, 8(%rax)
.L140:
	movq	-80(%rbp), %rax
	movq	%rax, %rdi
	call	readdir
	movq	%rax, -88(%rbp)
	cmpq	$0, -88(%rbp)
	jne	.L146
	movq	-80(%rbp), %rax
	movq	%rax, %rdi
	call	closedir
	movq	-66768(%rbp), %rax
	addq	$24, %rax
	movq	(%rax), %rcx
	leaq	-1168(%rbp), %rax
	movl	$12, %edx
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	strncpy
	leaq	-1168(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	movl	%eax, -100(%rbp)
	leaq	-1168(%rbp), %rax
	movq	%rax, -48(%rbp)
	jmp	.L147
.L148:
	movq	-48(%rbp), %rax
	movzbl	(%rax), %eax
	movzbl	%al, %eax
	movl	%eax, %edi
	call	toupper
	movl	%eax, %edx
	movq	-48(%rbp), %rax
	movb	%dl, (%rax)
	addq	$1, -48(%rbp)
.L147:
	movq	-48(%rbp), %rax
	movzbl	(%rax), %eax
	testb	%al, %al
	jne	.L148
	movq	-66768(%rbp), %rax
	addq	$16, %rax
	movq	(%rax), %rax
	movq	%rax, %rdi
	call	strlen
	movl	%eax, -20(%rbp)
	movq	-66768(%rbp), %rax
	addq	$16, %rax
	movq	(%rax), %rax
	movl	-20(%rbp), %edx
	movslq	%edx, %rdx
	subq	$1, %rdx
	addq	%rdx, %rax
	movzbl	(%rax), %eax
	cmpb	$46, %al
	jne	.L149
	subl	$1, -20(%rbp)
.L149:
	movl	-20(%rbp), %eax
	movslq	%eax, %rdx
	movq	-66768(%rbp), %rax
	addq	$16, %rax
	movq	(%rax), %rcx
	leaq	-896(%rbp), %rax
	movq	%rcx, %rsi
	movq	%rax, %rdi
	call	strncpy
	movl	-20(%rbp), %eax
	cltq
	movb	$0, -896(%rbp,%rax)
	movl	$0, -24(%rbp)
	jmp	.L150
.L151:
	movl	-24(%rbp), %eax
	cltq
	movzbl	-896(%rbp,%rax), %eax
	movzbl	%al, %eax
	movl	%eax, %edi
	call	tolower
	movl	%eax, %edx
	movl	-24(%rbp), %eax
	cltq
	movb	%dl, -896(%rbp,%rax)
	addl	$1, -24(%rbp)
.L150:
	movl	-24(%rbp), %eax
	cmpl	-20(%rbp), %eax
	jl	.L151
	leaq	-896(%rbp), %rax
	movl	$.LC28, %esi
	movq	%rax, %rdi
	call	strcmp
	testl	%eax, %eax
	jne	.L152
	leaq	-1168(%rbp), %rax
	movl	$.LC0, %esi
	movq	%rax, %rdi
	call	strcmp
	testl	%eax, %eax
	jne	.L152
	leaq	-896(%rbp), %rdx
	leaq	-66736(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	special_manyhome
	jmp	.L169
.L152:
	cmpl	$13, -20(%rbp)
	jle	.L153
	movl	-20(%rbp), %eax
	cltq
	leaq	-14(%rax), %rdx
	leaq	-896(%rbp), %rax
	addq	%rdx, %rax
	movl	$.LC29, %esi
	movq	%rax, %rdi
	call	strcmp
	testl	%eax, %eax
	jne	.L153
	leaq	-896(%rbp), %rdx
	leaq	-66736(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	special_again
	jmp	.L169
.L153:
	cmpl	$12, -20(%rbp)
	jle	.L154
	movl	-20(%rbp), %eax
	cltq
	leaq	-13(%rax), %rdx
	leaq	-896(%rbp), %rax
	addq	%rdx, %rax
	movl	$.LC30, %esi
	movq	%rax, %rdi
	call	strcmp
	testl	%eax, %eax
	jne	.L154
	movl	$3, %eax
	jmp	.L169
.L154:
	leaq	-896(%rbp), %rax
	movl	$46, %esi
	movq	%rax, %rdi
	call	strchr
	testq	%rax, %rax
	jne	.L155
	cmpq	$0, -40(%rbp)
	je	.L155
	leaq	-896(%rbp), %rax
	movl	$.LC31, %esi
	movq	%rax, %rdi
	call	strcmp
	testl	%eax, %eax
	je	.L155
	movq	-40(%rbp), %rdx
	leaq	-896(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	strcat
	movq	-40(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	addl	%eax, -20(%rbp)
.L155:
	movl	$0, -24(%rbp)
	jmp	.L156
.L160:
	movl	-24(%rbp), %eax
	cltq
	salq	$4, %rax
	leaq	-16(%rbp), %rbx
	addq	%rbx, %rax
	subq	$624, %rax
	movq	(%rax), %rax
	movq	%rax, -56(%rbp)
	movq	-56(%rbp), %rax
	movq	%rax, %rdi
	call	strlen
	movl	%eax, -104(%rbp)
	movq	-56(%rbp), %rax
	leaq	1(%rax), %rdx
	leaq	-896(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	strcmp
	testl	%eax, %eax
	je	.L157
	movl	-20(%rbp), %eax
	cmpl	-104(%rbp), %eax
	jl	.L158
	movl	-20(%rbp), %eax
	movslq	%eax, %rdx
	movl	-104(%rbp), %eax
	cltq
	subq	%rax, %rdx
	leaq	-896(%rbp), %rax
	addq	%rax, %rdx
	movq	-56(%rbp), %rax
	movq	%rax, %rsi
	movq	%rdx, %rdi
	call	strcmp
	testl	%eax, %eax
	jne	.L158
.L157:
	movl	-24(%rbp), %eax
	cltq
	salq	$4, %rax
	leaq	-16(%rbp), %rbx
	addq	%rbx, %rax
	subq	$624, %rax
	movq	8(%rax), %rax
	movq	%rax, -64(%rbp)
	jmp	.L159
.L158:
	addl	$1, -24(%rbp)
.L156:
	movl	-24(%rbp), %eax
	cmpl	-28(%rbp), %eax
	jl	.L160
.L159:
	cmpq	$0, -64(%rbp)
	jne	.L161
	movq	stderr(%rip), %rax
	leaq	-896(%rbp), %rdx
	movl	$.LC32, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	fprintf
	movl	$5, %eax
	jmp	.L169
.L161:
	movq	-66768(%rbp), %rax
	addq	$8, %rax
	movq	(%rax), %rdx
	movq	-64(%rbp), %rcx
	leaq	-1152(%rbp), %rax
	movl	$.LC33, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	sprintf
	leaq	-66736(%rbp), %rax
	movl	$12, %edx
	movl	$0, %esi
	movq	%rax, %rdi
	call	memset
	movq	-66744(%rbp), %rax
	addq	$12, %rax
	movq	%rax, -66744(%rbp)
	leaq	-1152(%rbp), %rax
	movl	$.LC34, %esi
	movq	%rax, %rdi
	call	fopen
	movq	%rax, -112(%rbp)
	cmpq	$0, -112(%rbp)
	jne	.L162
	call	__errno_location
	movl	(%rax), %eax
	movl	%eax, %edi
	call	strerror
	movq	%rax, %rcx
	movq	stderr(%rip), %rax
	leaq	-1152(%rbp), %rdx
	movl	$.LC35, %esi
	movq	%rax, %rdi
	movl	$0, %eax
	call	fprintf
	movl	$3, %eax
	jmp	.L169
.L162:
	movl	$0, -120(%rbp)
	subq	$8, %rsp
	leaq	-66744(%rbp), %r9
	movl	-100(%rbp), %r8d
	leaq	-1168(%rbp), %rcx
	leaq	-896(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	-112(%rbp), %rax
	leaq	-66752(%rbp), %rdi
	pushq	%rdi
	leaq	-66748(%rbp), %rdi
	pushq	%rdi
	leaq	-120(%rbp), %rdi
	pushq	%rdi
	movq	%rax, %rdi
	call	find_records
	addq	$32, %rsp
	movl	%eax, -116(%rbp)
	cmpl	$3, -116(%rbp)
	jne	.L163
	jmp	.L164
.L163:
	movl	-120(%rbp), %eax
	movzwl	%ax, %eax
	movl	%eax, %edi
	call	htons
	movl	%eax, %edx
	movq	-72(%rbp), %rax
	movw	%dx, 6(%rax)
	movl	-66752(%rbp), %eax
	testl	%eax, %eax
	je	.L165
	movq	-56(%rbp), %rax
	movzbl	(%rax), %eax
	cmpb	$46, %al
	jne	.L166
	movq	-56(%rbp), %rax
	addq	$1, %rax
	jmp	.L167
.L166:
	movq	-56(%rbp), %rax
.L167:
	subq	$8, %rsp
	leaq	-66744(%rbp), %rcx
	movq	-56(%rbp), %rsi
	movq	-112(%rbp), %rdi
	pushq	$0
	pushq	$0
	leaq	-120(%rbp), %rdx
	pushq	%rdx
	movq	%rcx, %r9
	movl	$2, %r8d
	movl	$.LC1, %ecx
	movq	%rax, %rdx
	call	find_records
	addq	$32, %rsp
.L165:
	movl	-120(%rbp), %eax
	movl	%eax, %ebx
	movq	-72(%rbp), %rax
	movzwl	6(%rax), %eax
	movzwl	%ax, %eax
	movl	%eax, %edi
	call	ntohs
	subl	%eax, %ebx
	movl	%ebx, %eax
	movzwl	%ax, %eax
	movl	%eax, %edi
	call	htons
	movl	%eax, %edx
	movq	-72(%rbp), %rax
	movw	%dx, 8(%rax)
	movq	-72(%rbp), %rax
	movw	$0, 10(%rax)
	movl	-66748(%rbp), %eax
	testl	%eax, %eax
	je	.L168
	movq	-72(%rbp), %rax
	movzbl	3(%rax), %edx
	orl	$32, %edx
	movb	%dl, 3(%rax)
.L168:
	movl	-66752(%rbp), %eax
	testl	%eax, %eax
	je	.L164
	movq	-72(%rbp), %rax
	movzbl	2(%rax), %edx
	orl	$4, %edx
	movb	%dl, 2(%rax)
.L164:
	movq	-112(%rbp), %rax
	movq	%rax, %rdi
	call	fclose
	movq	stdout(%rip), %rdx
	movq	-66744(%rbp), %rax
	movq	%rax, %rcx
	leaq	-66736(%rbp), %rax
	subq	%rax, %rcx
	movq	%rcx, %rax
	movq	%rax, %rsi
	leaq	-66736(%rbp), %rax
	movq	%rdx, %rcx
	movq	%rsi, %rdx
	movl	$1, %esi
	movq	%rax, %rdi
	call	fwrite
	movl	-116(%rbp), %eax
.L169:
	movq	-8(%rbp), %rbx
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE13:
	.size	main, .-main
	.ident	"GCC: (Debian 4.9.2-10) 4.9.2"
	.section	.note.GNU-stack,"",@progbits
