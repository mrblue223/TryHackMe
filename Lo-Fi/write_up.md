## TryHackMe | LoFi challenge

## First look at the webpage

![Alt text for the image](webpage.png)

## Look at the vulnrable part of the source code, Local File Inclusion (LFI)

![Alt text for the image](vuln.png)

Then we use path traversal to read the contents of the file.
    
- We can gather users from /etc/passwd

![Alt text for the image](etc.png)

- We can get our flag from /var/www/html/flag.txt or ../../../../flag.txt

![Alt text for the image](flag.png)
