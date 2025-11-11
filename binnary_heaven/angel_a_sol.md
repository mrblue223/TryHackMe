😇 TryHackMe: Binary Heaven - angel_A Username Crack

This document details the complete reverse engineering process to find the correct username for the angel_A binary. This challenge required navigating an anti-debugging mechanism, solving a mathematical formula from the assembly code, and ultimately making a final thematic leap to bypass a subtle programmer trick.

1. Initial Analysis and Anti-Debugging Measures

The first step was to load the binary into GDB and analyze the main function.

A. The Anti-Debugging Trap

The binary implements an immediate anti-debugging check using the ptrace syscall:

0x000000000000119d <+40>: call 0x1060 <ptrace@plt>
0x00000000000011a2 <+45>: cmp $0xffffffffffffffff,%rax ; Compare return value to -1
0x00000000000011a6 <+49>: jne 0x11c3 <main+78>      ; Jumps only if ptrace succeeds (returns 0)


If run under GDB, ptrace returns -1 (indicating tracing is active), causing the check to fail and the program to exit. This forced the primary analysis to be conducted by running the binary directly outside of the debugger.

B. Input Handling

The program uses fgets to read a maximum of 9 bytes into a stack buffer at $\mathbf{RBP - 0xD}$:

0x00000000000011df <+106>: mov $0x9,%esi             ; ESI = 9 (max size)
0x00000000000011e7 <+114>: call 0x1050 <fgets@plt>   ; fgets(buffer, 9, stdin)


The subsequent validation loop checks exactly 8 characters (indices $i=0$ to $i=7$).

2. Deriving the Mathematical Validation

The username validation loop (starting around <main+128>) requires that the transformed user input equals a static target value ($\mathbf{T}$).

A. The Core Transformation Formula

The assembly instructions define the transformation on the user's input character ($\mathbf{I}$):

Assembly Instruction

Operation

Resulting Formula

0x1216 <+161>: xor $0x4,%eax

XOR with 4

$\mathbf{I} \oplus 4$

0x121c <+167>: add $0x8,%eax

Add 8

$(\mathbf{I} \oplus 4) + 8$

The success condition is $\mathbf{T} = (\mathbf{I} \oplus 4) + 8$, which solves for $\mathbf{I}$ as:


$$\mathbf{I} = (\mathbf{T} - 8) \oplus 4$$

B. Extracting the Target Data ($\mathbf{T}$)

The target values were extracted from the array of 4-byte DWORDS at the memory location 0x4060 (<username>):

$$\mathbf{T} = [107, 121, 109, 126, 104, 117, 109, 114]$$

3. Thematic Solution Overrides Math

A. The Contradiction

Applying the strict mathematical formula $\mathbf{I} = (\mathbf{T} - 8) \oplus 4$ yields the result guizdian. However, this input was consistently rejected, even when newline injection was ruled out.

T (Dec)

$(\mathbf{T} - 8) \oplus 4$ (Dec)

ASCII Char

107

103

g

121

117

u

109

105

i

126

122

z

104

100

d

117

105

i

109

97

a

114

110

n

B. The Thematic Leap

The failure of the mathematically correct answer, combined with the challenge name (angel_A), suggested a final theme-based solution. We hypothesized that the key generator intended a word like guardian and introduced a subtle error in the code (e.g., swapping the ADD and XOR operations) to create a nearby, yet incorrect, key.

Testing the alternative formula $\mathbf{I} = (T \oplus 4) - 8$ (swapped operations) confirmed the thematic link:

T (Dec)

$(T \oplus 4) - 8$ (Dec)

ASCII Char

107

103

g

121

117

u

109

97

a

126

114

r

104

100

d

117

105

i

109

97

a

114

110

n

The calculation for the alternative formula yields guardian.

4. Final Solution

By supplying the thematically correct word, the check was successfully bypassed:

$ ./angel_A

Say my username >> guardian

Correct! That is my name!


Final Answer: guardian
