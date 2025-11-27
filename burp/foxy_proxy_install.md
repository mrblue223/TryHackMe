Generate a comprehensive, step-by-step tutorial using **raw GitHub Flavored Markdown (GFM)** syntax for configuring **Burp Suite** with the **FoxyProxy** browser extension.

The tutorial must be divided into three main sections, clearly separated by horizontal rules (`***`):

1.  **Part 1: Burp Suite & FoxyProxy Configuration**
    * Detail starting Burp Suite and setting up the Proxy Listener on `127.0.0.1:8080`.
    * Detail installing FoxyProxy and setting up a manual proxy profile pointing to `127.0.0.1:8080`.
2.  **Part 2: Installing the Burp CA Certificate**
    * Detail navigating to `http://burp/` to download the `cacert.der` file (Downloading the Certificate).
    * Provide separate, clear instructions for installing the certificate in **Mozilla Firefox** (using its internal store) and **Google Chrome / Microsoft Edge** (using the OS store/Certificate Import Wizard).
    * Use bolding to emphasize important steps (e.g., **Trusted Root Certification Authorities**).
3.  **Part 3: Verification**
    * Detail how to test the setup by intercepting an HTTPS request (e.g., `https://portswigger.net`) in Burp Suite and verifying no browser certificate warnings appear.

Use emojis, bolding, and headings (`#`, `##`, `###`) to enhance clarity and scannability.
