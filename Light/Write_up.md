## Exploiting Light Database - SQL Injection Walkthrough

This repository details the process of exploiting a "Light database" application through SQL injection, ultimately leading to the retrieval of administrator credentials and the flag.

Note: For the images to display correctly on GitHub, please ensure that all image files (password_for_smokey.png, error.png, interesting_error.png, sql_discovery.png, db_dump.png, flag.png) are located in the same directory as this README.md file in your GitHub repository.
## 1. Initial Access and Reconnaissance

We began by connecting to the target service, which was listening on port 1337. This service presented a "Light database" login prompt.

To establish a connection, we used netcat:

nc 10.10.50.126 1337

Upon successful connection, we were greeted by the login screen. We were provided with an initial username "smokey" and its corresponding password "vYQ5ngPpw8AdUmL".
## 2. SQL Injection Discovery

Our first step in identifying potential vulnerabilities was to test for SQL injection. A common technique is to inject a single quote (') into the username field to observe the application's response.

When we entered ' as the username, the application returned an error:

The error message Error: unrecognized token: " LIMIT 30" confirmed that the application was indeed vulnerable to SQL injection. Furthermore, the error provided a valuable hint about the structure of the underlying SQL query, indicating the presence of a LIMIT 30 clause.
## 3. Bypassing Restrictions - Commenting

With the SQL injection vulnerability confirmed, our next attempt involved using a UNION SELECT statement. Typically, the remainder of the original query is commented out using -- or /* ... */.

However, when we tried to use -- (e.g., ' UNION SELECT 1 -- ) to comment out the trailing part of the query, we encountered an interesting restriction:

The application explicitly stated: "For strange reasons I can't explain, any input containing /*, --, or %0b is not allowed :)". This indicated a simple filter preventing common SQL comment syntaxes. To bypass this, we realized we would need to properly terminate our injected query with a single quote (') to close the original query, rather than relying on comments.
## 4. Identifying the Database Management System (DBMS)

To craft more precise payloads, it was crucial to identify the specific DBMS in use. For SQLite databases, the sqlite_version() function is commonly used to retrieve its version.

We injected the following payload into the username field:

' Union Select sqlite_version()'

This injection successfully returned the SQLite version:

The output 3.31.1 confirmed that the database was SQLite.
## 5. Extracting Database Schema

Knowing that the DBMS was SQLite, we could now leverage SQLite-specific features to extract the database schema. The sqlite_master table in SQLite contains metadata about all tables, indexes, views, and triggers. We used the group_concat(sql) function to retrieve the CREATE TABLE statements for all tables, which reveals their structure.

The payload used was:

' Union Select group_concat(sql) FROM sqlite_master'

Injecting this into the username field revealed the full database structure:

The output showed two tables: usertable and admintable. Both tables contained id, username, and password columns. Our objective was to find the credentials for the admin user, which were clearly located in the admintable.
## 6. Retrieving Admin Credentials and Flag

The final step was to dump the username and password fields from the admintable. To make the output clear, we concatenated the username and password with a colon (:) using the || operator (SQLite's string concatenation operator) and group_concat to display all entries if there were multiple.

The payload for this step was:

' Union Select group_concat(username || ":" || password) FROM admintable '

Upon executing this payload, we successfully retrieved the administrator's username, password, and the flag:

The output provided the following critical information: TryhackmeAdmin:mamZtAUhRseEy5bp6qJ7, flag:THM{SQliT3_InJ3cti0n_is_Simple_no?}

This concluded the SQL injection attack, allowing us to successfully retrieve the administrator credentials and the hidden flag.
