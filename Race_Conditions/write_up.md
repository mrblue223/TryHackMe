## TryHackMe | Race Conditions

## Challenge 1

The code is in anti_code_reader.c

## Explenation:
Secure Flag Reader: Intent vs. Vulnerability (https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)

This C program is designed as a secure flag reader. It takes a file path as an argument and performs two crucial security checks before proceeding:

    It verifies that the file path doesn't contain the string "flag."
    It ensures the file isn't a symbolic link.

If both checks pass, the program then prints the file's contents.
The Race Condition Vulnerability

Despite these checks, the program has a race condition vulnerability. This occurs because the program's outcome can be manipulated by the timing of external, uncontrollable events.

Specifically, there's a critical window after the security checks are completed but before the program opens the file for reading. A malicious user could exploit this window by quickly replacing the "safe" file (the one that passed the checks) with a symbolic link pointing to the sensitive "flag" file. Since the checks have already run, they won't detect this switch, and the program will unwittingly open and display the contents of the flag file.
Exploiting the Vulnerability

To demonstrate this vulnerability, we'll create a test file in the /home/race directory, as we lack permissions to create one in /home/walk.

To create this test file, you'll need to open another SSH session.

![Alt text for the image](we_wait.png)

![Alt text for the image](1.png)

Now in /home/walk we try to read the content of the test file. And we wait, dont press enter yet. In another ssh session follow the steps
of the left ssh session and you will get the flag

![Alt text for the image](flag1.png)

## Challenge 2

Next, we'll navigate to the /home/run directory and analyze the cat2.c code.

## Understanding the Race Condition in cat2.c

The cat2.c program, intended as a more secure version of cat, unfortunately harbors a race condition vulnerability. This flaw stems from a critical time gap between when the program performs a security context check and when it actually opens the file for reading.

Here's how it breaks down:

    Security Check: The program first verifies if the user has the necessary permissions to access the file.
    Vulnerable Window: Critically, there's a deliberate half-second pause (usleep(500)) immediately after this check. This artificial delay creates a window of opportunity for an attacker.
    File Open: After the pause, the program proceeds to open the file.

How the Exploit Works

An attacker can exploit this vulnerability by performing a precise file swap. Right after the program completes its security check, but just before the open() operation executes, the attacker can replace the legitimate file with a restricted file or a symbolic link to a restricted file. Because the security check has already passed, the program will then unknowingly open and process the unauthorized file.

Despite its design as a more secure cat command with extra user context checks, this timing discrepancy completely undermines its security, making it susceptible to exploitation.
Exploiting the Vulnerability

To demonstrate this vulnerability, we'll create a small bash script named run.sh in SSH session 2. 

The run.sh script is designed to rapidly create, replace, and delete a test file. Its goal is to insert a symbolic link pointing to the /home/run/flag file within the precise, brief window that exists between the vulnerable program's security checks and its subsequent open() operation.

If this timing attack is successful, the program will inadvertently read and output the contents of the flag file, completely bypassing its intended security measures.

To execute this exploit:

    In SSH session 2, run your script:
    Bash

bash run.sh

Simultaneously (or immediately after starting the script), in SSH session 1, execute the vulnerable command:
Bash

    ./cat /home/race/test

This synchronized execution aims to reveal the flag. (NOTE: you might need the spam the enter button in session two to make it work)

![Alt text for the image](flag2.png)

## Challenge 3

This was bit tricky challenge, and it needed a little bit of scripting knowledge to solve it.
