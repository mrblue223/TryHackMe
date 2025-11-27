# 🛠️ Burp Suite and FoxyProxy Complete Configuration Guide

This guide details the full process of integrating Burp Suite with the FoxyProxy browser extension, including the crucial step of installing the CA certificate for successful HTTPS interception.

***

## 1️⃣ Part 1: Burp Suite & FoxyProxy Configuration

This section ensures Burp Suite is running and FoxyProxy is set up to point to it. 

1.  **Start Burp Suite**
    * Launch Burp Suite Professional or Community Edition.
    * Select the **Proxy** tab, then the **Options** sub-tab.
    * Under **Proxy Listeners**, verify there is an entry (usually `127.0.0.1:8080`). If not, click **Add** and set the **Bind to address** to `Loopback interface only` and **Bind to port** to `8080`.
2.  **Install FoxyProxy Extension**
    * Open your browser (Firefox or Chrome).
    * Install the **FoxyProxy Standard** extension from the respective browser store.
3.  **Configure FoxyProxy Profile**
    * Click the **FoxyProxy icon** and select **Options**.
    * Click **Add New Proxy**.
    * In the **General** tab, set a **Title** (e.g., `Burp Suite`) and an optional **Color**.
    * In the **Proxy Details** tab, select **Manual Proxy Configuration**.
    * Set **Host or IP Address** to `127.0.0.1`.
    * Set **Port** to `8080`.
    * Ensure the box **"SOCKS proxy?"** is **UNCHECKED**.
    * Click **Save**.
4.  **Activate FoxyProxy**
    * Click the **FoxyProxy icon** again.
    * Select the profile you just created (e.g., `Burp Suite`) to switch your browser's traffic to Burp.

***

## 2️⃣ Part 2: Installing the Burp CA Certificate

This section is essential for allowing Burp Suite to correctly intercept HTTPS/SSL traffic without browser warnings.

1.  **Download the Certificate**
    * Ensure **Burp Suite is running** and **FoxyProxy is active** (pointing to Burp).
    * In the proxied browser, navigate to the URL: `http://burp/`
    * On the Burp Suite page, click the **"CA Certificate"** button (top right).
    * Save the file, typically named **`cacert.der`** or **`cert.der`**.
2.  **Install Certificate (Browser/OS Specific)**

    * ### **Browser: Mozilla Firefox** (Uses its own store) 
        * Go to **Firefox Settings** ($\equiv$).
        * Search for **"Certificates"** and click **"View Certificates"**.
        * Go to the **Authorities** tab.
        * Click **Import...**
        * Select the downloaded **`cacert.der`** file.
        * Check the box: **"Trust this CA to identify websites."**
        * Click **OK**.

    * ### **Browser: Google Chrome / Microsoft Edge (Windows)** (Uses OS store) 
        * Open your file explorer and **double-click** the **`cacert.der`** file.
        * The **Certificate Import Wizard** will open.
        * Select **Current User** or **Local Machine**.
        * Choose **"Place all certificates in the following store."**
        * Click **Browse...**
        * Select the **Trusted Root Certification Authorities** folder.
        * Click **OK**, then **Next**, then **Finish**.
        * Click **Yes** on any security warning to complete the trust import.

***

## 3️⃣ Part 3: Verification

1.  **Test Interception**
    * In **Burp Suite**, go to **Proxy** $\to$ **Intercept**.
    * Ensure **Intercept is on**.
  
## Part 4: Remember
### Remember the following:
- When the proxy configuration is active, and the intercept is switched on in Burp Suite, your browser will hang whenever you make a request.
- Be cautious not to leave the intercept switched on unintentionally, as it can prevent your browser from making any requests.
- Right-clicking on a request in Burp Suite allows you to perform various actions, such as forwarding, dropping, sending to other tools, or selecting options from the right-click menu.

-  If successful, the request will be **held** in the Burp Suite **Intercept** tab, and the browser will be waiting for a response without displaying any SSL/Certificate warnings.
-  lick **Forward** in Burp Suite to allow the request to continue.
