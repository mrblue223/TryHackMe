## Capture_returns | TryHackMe
To use the captcha-solver.py script, follow these steps:

    Save the script: Save the provided Python code as captcha-solver.py.
    Create usernames.txt: In the same directory as the script, create a file named usernames.txt. Each line in this file should contain one username you want to try for login.
    Create passwords.txt: Also in the same directory, create a file named passwords.txt. Each line in this file should contain one password.
    Install prerequisites:
        Python 3: Ensure you have Python 3 installed.
        Tesseract OCR: Install Tesseract OCR on your system. For Debian/Ubuntu, use sudo apt-get install tesseract-ocr; for macOS, use brew install tesseract.
        Python Libraries: Install the necessary Python libraries using pip: pip install Pillow requests opencv-python numpy beautifulsoup4 pytesseract.
    Run the script: Open your terminal or command prompt, navigate to the directory where you saved the script, and run it using the command: python captcha-solver.py.

The script will then attempt to log in using the provided usernames and passwords, solving CAPTCHAs as it encounters them. It will print its progress to the console and save the full HTML responses of each attempt to a file named response.txt.

## Running the script
    python captcha-solver.py
