# Burp Suite Encyclopedia: The Definitive Guide (Raw Markdown)

## Table of Contents

* [I. Burp Suite Core Architecture and Deployment](#i-burp-suite-core-architecture-and-deployment)
    * [A. Editions and Feature Delineation](#a-editions-and-feature-delineation)
    * [B. Core Setup and Initial Configuration](#b-core-setup-and-initial-configuration)
        * [1. HTTP Proxy Listener Setup](#1-http-proxy-listener-setup)
        * [2. TLS/HTTPS Interception and Certificate Installation](#2-tlshttps-interception-and-certificate-installation)
        * [3. Scope Definition and Management (Target Tab)](#3-scope-definition-and-management-target-tab)
* [II. Essential Manual Tools (Community & Professional)](#ii-essential-manual-tools-community--professional)
    * [A. Proxy Tool](#a-proxy-tool)
        * [1. Intercept Sub-tab](#1-intercept-sub-tab)
        * [2. HTTP History Sub-tab](#2-http-history-sub-tab)
        * [3. WebSocket History](#3-websocket-history)
    * [B. Repeater Tool](#b-repeater-tool)
        * [1. Basic Workflow](#1-basic-workflow)
        * [2. Analysis Features](#2-analysis-features)
    * [C. Decoder Tool](#c-decoder-tool)
        * [1. Encoding and Decoding Support](#1-encoding-and-decoding-support)
    * [D. Comparer Tool](#d-comparer-tool)
        * [1. Comparison Modes](#1-comparison-modes)
    * [E. Sequencer Tool (Token Analysis)](#e-sequencer-tool-token-analysis)
        * [1. Purpose](#1-purpose)
        * [2. Core Statistical Tests](#2-core-statistical-tests)
* [III. Automated Attack Tool: Intruder (Professional Features)](#iii-automated-attack-tool-intruder-professional-features)
    * [A. The Four Attack Types (The Core Mechanism)](#a-the-four-attack-types-the-core-mechanism)
    * [B. Payload Configuration](#b-payload-configuration)
        * [1. Payload Sets](#1-payload-sets)
        * [2. Payload Types (Generators)](#2-payload-types-generators)
        * [3. Payload Processing](#3-payload-processing)
    * [C. Intruder Attack Settings and Grep](#c-intruder-attack-settings-and-grep)
        * [1. Attack Options (Settings Tab)](#1-attack-options-settings-tab)
* [IV. Automated Scanning and Auditing (Professional Only)](#iv-automated-scanning-and-auditing-professional-only)
    * [A. The Crawl Phase (Discovery)](#a-the-crawl-phase-discovery)
    * [B. The Audit Phase (Scanning)](#b-the-audit-phase-scanning)
        * [1. Passive Audit Phase](#1-passive-audit-phase)
        * [2. Active Audit Phase](#2-active-audit-phase)
        * [3. JavaScript Analysis Phase](#3-javascript-analysis-phase)
    * [C. Advanced Scan Configuration and Insertion Points](#c-advanced-scan-configuration-and-insertion-points)
* [V. Out-of-Band Application Security Testing (OAST) via Collaborator](#v-out-of-band-application-security-testing-oast-via-collaborator)
    * [A. Collaborator Concept](#a-collaborator-concept)
    * [B. Vulnerabilities Detected by OAST](#b-vulnerabilities-detected-by-oast)
    * [C. Collaborator Usage](#c-collaborator-usage)
* [VI. Extensibility, Customization, and Automation](#vi-extensibility-customization-and-automation)
    * [A. The Extender Tab and BApp Store](#a-the-extender-tab-and-bapp-store)
    * [B. BChecks (Custom Scan Checks)](#b-bchecks-custom-scan-checks)
    * [C. Bambdas (Custom Filters and Enhancements)](#c-bambdas-custom-filters-and-enhancements)
* [VII. Advanced Workflow and Project Settings](#vii-advanced-workflow-and-project-settings)
    * [A. Session Handling (Project Options > Sessions)](#a-session-handling-project-options--sessions)
    * [B. Macros (Project Options > Sessions > Macros)](#b-macros-project-options--sessions--macros)
    * [C. Logging and Reporting](#c-logging-and-reporting)
    * [D. Upstream Proxy Settings (User Options > Connections)](#d-upstream-proxy-settings-user-options--connections)
* [VIII. Advanced Testing Methodologies and Specific Exploits](#viii-advanced-testing-methodologies-and-specific-exploits)
    * [A. Parameter Tampering and Fuzzing](#a-parameter-tampering-and-fuzzing)
    * [B. Cross-Site Request Forgery (CSRF)](#b-cross-site-request-forgery-csrf)
    * [C. Time-Based and Blind Attacks](#c-time-based-and-blind-attacks)
    * [D. Testing JSON Web Tokens (JWTs)](#d-testing-json-web-tokens-jwts)
* [IX. Environment and Resource Management (User/Project Options)](#ix-environment-and-resource-management-userproject-options)
    * [A. User Options (Global Settings)](#a-user-options-global-settings)
    * [B. Project Options (Session/Project Specific)](#b-project-options-sessionproject-specific)
* [X. Summary of Key Burp Keyboard Shortcuts](#x-summary-of-key-burp-keyboard-shortcuts)

***

## I. Burp Suite Core Architecture and Deployment

### A. Editions and Feature Delineation

| Feature | Community Edition | Professional Edition | Enterprise Edition |
| :--- | :--- | :--- | :--- |
| **Proxy** | Full Intercept/History | Full Intercept/History | N/A (Headless DAST) |
| **Repeater** | Full Functionality | Full Functionality | N/A |
| **Intruder** | Rate-limited, Basic Payloads | Full Speed, All Attack Types, Advanced Payloads | N/A |
| **Scanner** | Passive only (Live Passive Crawl) | **Full Automated** Active/Passive/JS/OAST Scanner | Scalable DAST for CI/CD |
| **Sequencer** | Full Functionality | Full Functionality | N/A |
| **Comparer/Decoder**| Full Functionality | Full Functionality | N/A |
| **Extensibility (BApps)** | Limited Support | **Full** BApp Store & Extender API/Montoya API | N/A |
| **Collaborator** | N/A | **Full** Out-of-Band (OAST) Integration | Full OAST Integration |
| **Project Management** | Temporary Projects Only | **Save/Restore** Projects, Configuration Library | N/A |

***

### B. Core Setup and Initial Configuration

#### 1. HTTP Proxy Listener Setup

* **Default Configuration:** The Burp Proxy is set by default to listen on loopback interface (`127.0.0.1`) and port `8080`.
* **Listener Modification:** You can configure additional listeners for testing mobile apps or segregated network zones via the **Proxy > Options** tab.
    * *Bind to Address:* Specifies the interface (e.g., `127.0.0.1`, `All interfaces`, or a specific IP).
    * *Bind to Port:* Specifies the TCP port number.
* **Browser Configuration:** The target browser must be configured to use Burp's listening address as its proxy server.
    * **FoxyProxy:** Recommended browser extension for quick switching between proxy configurations.
        * **Proxy Type:** HTTP.
        * **IP Address:** `127.0.0.1`.
        * **Port:** `8080`.

#### 2. TLS/HTTPS Interception and Certificate Installation

* **Problem:** Burp acts as a **Man-in-the-Middle (MITM)** proxy, dynamically generating a server certificate for the target site, signed by its own Certificate Authority (CA). Browsers do not trust this CA by default, resulting in a **certificate warning**.
* **Solution (CA Import):**
    1.  Ensure the Burp Proxy is running.
    2.  Navigate to `http://burp/cert` in the configured browser.
    3.  Download the `cacert.der` file.
    4.  Access the browser's certificate manager (e.g., `about:preferences` in Firefox, then search for **"certificates"** and click **View Certificates**).
    5.  Import the `cacert.der` file.
    6.  Check the box to **"Trust this CA to identify websites"**.

#### 3. Scope Definition and Management (Target Tab)

* **Purpose:** To clearly define which URLs and hosts are part of the assessment target, reducing noise and preventing unauthorized scanning.
* **In-Scope Settings (Target > Scope sub-tab):** Contains a list of URL prefixes that are explicitly included.
    * *Inclusion Rule Types:* Protocol (`HTTP/HTTPS`), Host/IP, Port, and File path. Regular expressions can be used.
* **Exclusion Rules:** Define hosts or paths within the scope that should be ignored (e.g., static content).
* **Filtering:** The **Proxy > HTTP history** and **Target > Site map** can be filtered using the **"Show only in-scope items"** option.
* **Interception Filtering:** Advanced control in **Proxy > Options > Intercept Client Requests** allows requests to be forwarded automatically *unless* they match the scope (e.g., `And URL Is in target scope`).

***

## II. Essential Manual Tools (Community & Professional)

### A. Proxy Tool

The Proxy is the fundamental tool for intercepting, viewing, and modifying all traffic between your browser and the web application.

#### 1. Intercept Sub-tab
* **Function:** Holds requests captured by the proxy before they reach the server.
* **State:** The "**Intercept is on/off**" button controls traffic flow. When **On**, the browser stalls waiting for a tester action.
* **Actions:** **Forward** (sends the request), **Drop** (discards the request).

#### 2. HTTP History Sub-tab
* **Function:** A comprehensive log of all requests and responses that passed through the proxy.
* **Key Columns:** **#** (Index), **Host**, **Method** (HTTP verb), **URL**, **Status** (HTTP response status code), **Length** (response body size), and **Time**.
    * The **Length** column is crucial for identifying differences in content when conducting blind tests.
* **Filtering & Searching:** Advanced filters allow searching by status code, MIME type, parameter name, or regex pattern.

#### 3. WebSocket History
* **Function:** Logs all WebSocket messages (frames) sent and received, allowing review and manual modification of real-time communication.
* **Message View:** Shows individual frames with details on direction (client/server) and payload content.

### B. Repeater Tool

#### 1. Basic Workflow
* **Request Initiation:** Requests are sent from the Proxy History or Site Map to Repeater using the context menu (`Send to Repeater`).
* **Tabs:** Each request gets its own tab (`#1`, `#2`, etc.), allowing parallel testing.
* **Modification & Resend:** The tester manually edits the **Request** pane and clicks **"Send"**. The response is loaded immediately in the **Response** pane.

#### 2. Analysis Features
* **Response View Modes:**
    * **Raw:** Complete HTTP response (headers and body).
    * **Pretty:** Formats content (HTML, JSON, XML) for better readability.
    * **Hex:** Displays data in hexadecimal format.
    * **Render:** Displays the response content as rendered by a browser.
* **Inspector:** A side panel providing a structured, easy-to-modify view of the request/response parameters and headers.

### C. Decoder Tool

#### 1. Encoding and Decoding Support
* **Function:** Performs various transformations on data segments.
* **Common Formats:** **URL**, **HTML**, **Base64**, **ASCII/Hex**.
* **Smart Decoding:** Attempts to automatically detect and chain multiple encodings (e.g., Base64 followed by URL encoding).

### D. Comparer Tool

#### 1. Comparison Modes
* **Function:** Compares two requests or two responses to identify subtle differences.
* **Comparison Modes:**
    * **Word Comparison:** Highlights differences at the word (space-separated) level.
    * **Byte Comparison:** Highlights differences byte-by-byte. Essential for detecting tiny changes in response size or specific single-character output.

### E. Sequencer Tool (Token Analysis)

#### 1. Purpose
* **Function:** Evaluates the randomness and predictability of security tokens (e.g., session IDs, CSRF tokens).
* **Capture Phase:** Captures a large sample set of tokens for analysis.

#### 2. Core Statistical Tests
* **Statistical Analysis:** Conducts tests like **Monobit Test**, **Poker Test**, **Runs Test**, and **Chi-Squared Test**.
    * *Result:* Low entropy scores indicate predictable generation and a potential vulnerability.

***

## III. Automated Attack Tool: Intruder (Professional Features)

Intruder allows for systematic, high-speed injection of payloads into request parameters.

### A. The Four Attack Types (The Core Mechanism)

| Attack Type | Payload Sets | Mechanism | Ideal Use Case |
| :--- | :--- | :--- | :--- |
| **Sniper** | Single | Places each payload into **one position at a time**. | Fuzzing every parameter individually for XSS, SQLi, etc. |
| **Battering Ram**| Single | Places the **same payload into ALL defined positions simultaneously**. | Testing for logic flaws requiring identical inputs in multiple fields. |
| **Pitchfork** | Multiple (one set per position) | Places payloads by **index (one-to-one mapping)**. | Brute-forcing with two related lists (e.g., corresponding usernames and known passwords). |
| **Cluster Bomb**| Multiple (one set per position) | Tests **every possible permutation/combination** (cross-product). | Exhaustive brute-forcing with two unrelated lists (e.g., guessing unrelated username and password pairs). |

### B. Payload Configuration

#### 1. Payload Sets
* Allows up to 20 separate payload sets for Pitchfork and Cluster Bomb attacks.

#### 2. Payload Types (Generators)
* **Simple list:** Static list of strings.
* **Numbers:** Generates a sequence of integers (for ID guessing).
* **Dates:** Generates sequential dates/times.
* **Null payloads:** Generates an arbitrary number of empty payloads (for DoS testing).
* **Recursively Grep:** Uses previous responses to generate the next payload (for multi-step attacks).

#### 3. Payload Processing
* A series of rules applied to the payload before insertion, essential for complex encoding chains.
* **Rules:** Add prefix/suffix, Match/Replace (regex), Encode (URL, Base64, Hex), Hash (MD5, SHA1).

### C. Intruder Attack Settings and Grep

#### 1. Attack Options (Settings Tab)
* **Request Engine:** Controls threads and throttling (**rate limiting**) to manage speed and prevent DoS/detection.
* **Grep - Match:** Defines strings to look for in responses (e.g., "Invalid password"). Adds a custom column to the results table, the **primary method for detecting success**.
* **Grep - Extract:** Extracts specific data from responses using regex (e.g., a hidden token).
* **Grep - Payloads:** Flags results where the *payload itself* is reflected in the response (useful for **Reflected XSS**).

***

## IV. Automated Scanning and Auditing (Professional Only)

### A. The Crawl Phase (Discovery)

* **Function:** Burp Scanner maps the application's attack surface, automatically following links, submitting forms, and processing JavaScript to build the **Site Map**.
* **JavaScript Analysis:** Burp's embedded browser processes client-side code to discover dynamically generated links and parameters.

### B. The Audit Phase (Scanning)

The audit phase injects payloads to test for vulnerabilities, operating in three stages:

#### 1. Passive Audit Phase
* **Mechanism:** Observes existing traffic without sending new requests.
* **Vulnerabilities Detected:** **Security Header Issues** (HSTS, CSP), **TLS/SSL Issues**, **Sensitive Data Exposure** (e.g., internal IP addresses in headers).

#### 2. Active Audit Phase
* **Mechanism:** Sends modified, malicious requests to probe insertion points.
* **Key Stages:**
    * Tests for **First-Order** issues (reflected XSS, SQLi).
    * Tests for **Stored Input** and **Second-Order** issues (by storing payloads and re-fetching pages).
    * Sends **Collaborator Payloads** to detect blind vulnerabilities (OAST).

#### 3. JavaScript Analysis Phase
* **Mechanism:** Uses static analysis to trace user-controlled data flow from a **source** to a **sink** in client-side code.
* **Vulnerabilities Detected:** **DOM-Based XSS** and **Client-Side Prototype Pollution**.
* **DOM Invader:** A feature in the built-in browser for dynamic DOM manipulation and source/sink analysis.

### C. Advanced Scan Configuration and Insertion Points

* **Insertion Point Options:** Controls where payloads are injected (URL query, POST body, cookies, specific headers).
* **Parameter Location Modification:** Tests if a parameter type can be moved (e.g., from URL to POST body) to bypass security measures like WAFs.
* **Resource Pools:** Manages thread and request limits for different scan tasks.

***

## V. Out-of-Band Application Security Testing (OAST) via Collaborator

### A. Collaborator Concept

* **Definition:** **Burp Collaborator** is an external network service (server) that listens for interactions (DNS, HTTP, SMTP) initiated by a vulnerable application **out-of-band** (not in the immediate response).
* **Process:** Burp generates a unique subdomain payload (e.g., `abc123def.oastify.com`), which is injected into the target. The Collaborator server logs any connection attempts made by the application to that unique URL.

### B. Vulnerabilities Detected by OAST

| Vulnerability | Interaction Type | Detection Mechanism |
| :--- | :--- | :--- |
| **Server-Side Request Forgery (SSRF)** | HTTP/HTTPS | Application fetches the Collaborator URL as an external resource. |
| **Blind XXE Injection** | DNS/HTTP | XML parser resolves an external entity (Collaborator URL). |
| **Blind OS Command Injection** | DNS/HTTP | Executed commands (`curl`, `wget`) make an outbound connection. |
| **Blind XSS (Stored)** | HTTP | Payload is rendered in a client's context, triggering a fetch to Collaborator. |

### C. Collaborator Usage

* **Automated:** Used by the Active Scanner.
* **Manual:** Go to **Burp menu > Burp Collaborator client** to generate a unique payload and poll for interactions (`Poll Now`).

***

## VI. Extensibility, Customization, and Automation

### A. The Extender Tab and BApp Store

* **Extender Tab:** Manages extensions (BApps).
* **API:** Extensions can be written in Java (using the modern **Montoya API** or legacy Extender API) or Python/Ruby (via Jython/JRuby).
* **BApp Store:** A marketplace of community-developed extensions (e.g., **Autorize** for authorization testing, **Logger++** for advanced logging).

### B. BChecks (Custom Scan Checks)

* **Definition:** A simple, purpose-built scripting language for creating custom scan checks without full extension development.
* **Key Features:** Conditional logic, Regex Matching, Custom Request Sending, easy **Collaborator Integration** (`{generate_collaborator_address()}`).
* **Location:** Managed under **Extender > BChecks**.

### C. Bambdas (Custom Filters and Enhancements)

* **Definition:** Lightweight code snippets for on-the-fly customization of Burp's filtering and display.
* **Use Cases:** Complex table filtering (e.g., Proxy History filtering by specific status code AND response length), Custom table columns, highly specific Match and Replace rules.

***

## VII. Advanced Workflow and Project Settings

### A. Session Handling (Project Options > Sessions)

* **Function:** Automated rules to **maintain a valid authenticated session** during long-running tasks.
* **Rules:** Define a check for session validity and a remedial action (e.g., re-login).

### B. Macros (Project Options > Sessions > Macros)

* **Function:** A recorded sequence of requests that can be replayed automatically (e.g., a **login macro**).
* **Usage:** Essential for re-authenticating when a session expires or retrieving anti-CSRF tokens.

### C. Logging and Reporting

* **Logger++ (Extension):** Highly recommended for a master, searchable log of all Burp traffic.
* **Generating Reports (Professional Only):** Export issues (HTML or XML format) from the **Dashboard > Issues** tab.

### D. Upstream Proxy Settings (User Options > Connections)

* **Function:** Configuring Burp to send its traffic through another proxy server (e.g., a corporate proxy or SOCKS proxy for an SSH tunnel) before reaching the target.

***

## VIII. Advanced Testing Methodologies and Specific Exploits

### A. Parameter Tampering and Fuzzing

* **IDOR (Insecure Direct Object Reference):** Modifying numerical IDs (e.g., `user_id=123` to `user_id=124`) using Intruder with **Numbers** payload type.
* **Input Fuzzing:** Using Intruder to systematically inject known vulnerability payloads (XSS, SQLi) from public wordlists.

### B. Cross-Site Request Forgery (CSRF)

* **PoC Generation:** Right-click a target request (e.g., change password) and select **"Engagement tools > Generate CSRF PoC"** to create a functional HTML exploit page.

### C. Time-Based and Blind Attacks

* **Time Delays:** Testing for time-delay SQLi or Command Injection.
    * **Tool:** Repeater (manual) or Intruder (using payloads like `sleep(5)`).
    * **Detection:** Requires monitoring the **Time** column in the Intruder results for significant, measurable delays (e.g., 5000ms).

### D. Testing JSON Web Tokens (JWTs)

* **Manual Testing:** Use **Decoder** to Base64-decode the Header and Payload sections of the token to view and modify the claims (e.g., changing `role` from `user` to `admin`).
* **Extensibility:** Dedicated BApps (like **JSON Web Tokens**) automate manipulation and common attacks (e.g., Algorithm confusion).

***

## IX. Environment and Resource Management (User/Project Options)

### A. User Options (Global Settings)

* **Display:** Controls theme (light/dark mode) and font size.
* **Connections:** Configures outbound connections (SOCKS proxy, upstream HTTP proxy, proxy authentication).
* **SSL/TLS:** Configures client-side certificates for applications that require them.

### B. Project Options (Session/Project Specific)

* **HTTP:** Defines HTTP protocol-specific settings (e.g., **HTTP/2** support).
* **SSL/TLS:** Defines specific protocols and cipher suites Burp should use when connecting to target servers.
* **Misc:** Includes **Scheduled Tasks** (e.g., running a macro periodically to keep a session alive) and settings for the **Embedded Browser**.

***

## X. Summary of Key Burp Keyboard Shortcuts

| Shortcut | Tool | Action |
| :--- | :--- | :--- |
| **Ctrl + R** | Any Message Tab | Send request to **Repeater**. |
| **Ctrl + I** | Any Message Tab | Send request to **Intruder**. |
| **Ctrl + S** | Any Message Tab | Send request to **Scanner**. |
| **Ctrl + D** | Any Message Tab | Send request to **Decoder**. |
| **Ctrl + U** | Proxy Intercept | **Forward** intercepted request. |
| **Ctrl + P** | Proxy Intercept | **Drop** intercepted request. |
| **Ctrl + Space** | Repeater/Intruder | Repeat/Send the current request. |
| **Ctrl + Shift + P** | Switch Tab | Jump to **Proxy** tab. |
| **Ctrl + Shift + R** | Switch Tab | Jump to **Repeater** tab. |

***
