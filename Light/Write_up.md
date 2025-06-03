Markdown

# Exploiting Light Database - SQL Injection Walkthrough

This repository details the process of exploiting a "Light database" application through SQL injection, ultimately leading to the retrieval of administrator credentials and the flag.

## Initial Access and Reconnaissance

The target is a network service listening on port 1337, which presents a "Light database" login prompt.

First, we establish a connection using `netcat`:

```bash
nc 10.10.50.126 1337

Upon connection, we are greeted by the login screen. We're provided with a username "smokey" and a password "vYQ5ngPpw8AdUmL".
SQL Injection Discovery

We suspect the application is vulnerable to SQL injection. A common first step is to try injecting a single quote (') into the username field to see if it causes an error.

As expected, inserting a single quote results in an Error: unrecognized token: " LIMIT 30". This error message confirms the presence of SQL injection vulnerability and gives us a hint about the original query structure (likely including a LIMIT 30 clause).
Bypassing Restrictions - Commenting

Our next step is to try a UNION SELECT statement. However, common SQL injection techniques often involve commenting out the rest of the original query using -- or /* ... */.

When we attempt to use -- to comment out the trailing part of the query (e.g., ' UNION SELECT 1 --), we encounter an interesting error message:

The application explicitly states that "any input containing /* -- or, %0b is not allowed". This indicates a simple filter in place, preventing common SQL comment syntaxes. This means we'll have to end our injected query with a single quote to properly terminate the original query without relying on comments.
Identifying the Database Management System (DBMS)

Since we know it's a database application and SQL injection is possible, identifying the specific DBMS can help us craft more effective payloads. We can try common functions to determine this. For SQLite, sqlite_version() is a good candidate.
SQL

' Union Select sqlite_version()'

By injecting this into the username field, we successfully retrieve the SQLite version:

This confirms that the database is SQLite version 3.31.1.
Extracting Database Schema

Knowing it's SQLite, we can now leverage SQLite-specific queries to extract the database schema. The sqlite_master table contains information about all tables and indexes in the database. We can use group_concat(sql) to get the CREATE TABLE statements for all tables.
SQL

' Union Select group_concat(sql) FROM sqlite_master'

Injecting this payload reveals the database structure:

From the output, we can see two tables: usertable and admintable. Both have id, username, and password columns. Our goal is to find the credentials for an admin user, which are likely stored in the admintable.
Retrieving Admin Credentials and Flag

Finally, to get the admin credentials and the flag, we can dump the username and password from the admintable. We'll concatenate the username and password with a colon for better readability.
SQL

' Union Select group_concat(username || ":" || password) FROM admintable '

Executing this payload yields the administrator's username, password, and the flag:

The output provides: TryhackmeAdmin:mamZtAUhRseEy5bp6qJ7, flag:THM{SQliT3_InJ3cti0n_iS_SiMpLE_nO?}

This completes the SQL injection attack, successfully retrieving the administrator credentials and the flag.
