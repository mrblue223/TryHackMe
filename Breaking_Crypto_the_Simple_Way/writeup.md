## Breaking Hashes
echo "1484c3a5d65a55d70984b4d10b1884bda8876c1d:CanYouGuessMySecret" > digest.txt
hashcat -a 0 -m 150 digest.txt /usr/share/wordlists/rockyou.txt
