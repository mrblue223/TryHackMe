from Crypto.Cipher import AES
from bs4 import BeautifulSoup
import binascii
import requests

### Variables ###
# Updated with your specific VM IP
URL = "http://10.81.139.223:5000/oracle"

### Oracle Interface ###
def chat_to_oracle(username):
    # This function sends the username to the oracle and extracts the hex ciphertext
    r = requests.post(URL, data = {'username' : username})
    soup = BeautifulSoup(r.text, 'html.parser')
    value = str(soup.find(id='encrypted-result').find('strong'))
    value = value.replace('<strong>', '').replace('</strong>', '')
    return value

### Calculate Block Size ###
def calculate_block_size():
    # Gradually grows the username until the ciphertext length increases twice to find the block size
    username = "A"
    original_length = len(chat_to_oracle(username))
    
    first_change_len = 1
    while (len(chat_to_oracle(username)) == original_length):
        username += "A"
        first_change_len += 1

    new_length = len(chat_to_oracle(username))
    second_change_len = first_change_len
    while (len(chat_to_oracle(username)) == new_length):
         username += "A"
         second_change_len += 1

    BLOCK_SIZE = second_change_len - first_change_len
    return BLOCK_SIZE

def split_ciphertext(ciphertext, block_size):
    # Splits the hex ciphertext into chunks based on the block size (hex = 2 chars per byte)
    block_size = block_size * 2
    chunks = [ ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size) ]
    return chunks

### Calculate the Offset ###
def calculate_offset(block_size):
    # Determines where the user input starts relative to the block boundaries
    initial_text = "A" * (block_size * 2)
    ciphertext = chat_to_oracle(initial_text)
    chunks = split_ciphertext(ciphertext, block_size)

    if (len(chunks) != len(set(chunks))):
        return 0

    offset = 0
    while (len(chunks) == len(set(chunks))):
        offset += 1
        initial_text = "B" + initial_text
        ciphertext = chat_to_oracle(initial_text)
        chunks = split_ciphertext(ciphertext, block_size)

    return offset

### The Attack Logic ###
def brute_force_next_byte(block_size, offset, recovered_secret):
    # Calculates the padding needed to push the next unknown secret byte into the last position of a block
    padding_len = (block_size - 1) - (len(recovered_secret) % block_size)
    input_padding = ("B" * offset) + ("A" * padding_len)
    
    ciphertext = chat_to_oracle(input_padding)
    chunks = split_ciphertext(ciphertext, block_size)
    
    target_block_index = (offset + padding_len + len(recovered_secret)) // block_size
    reference_chunk = chunks[target_block_index]

    # Brute force ASCII range to find a matching ciphertext block
    charlist = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_! '
    
    for char in charlist:
        test_input = input_padding + recovered_secret + char
        test_ciphertext = chat_to_oracle(test_input)
        test_chunks = split_ciphertext(test_ciphertext, block_size)
        
        if test_chunks[target_block_index] == reference_chunk:
            return char
    return None

if __name__ == '__main__':
    print("--- Initializing Attack ---")
    size = calculate_block_size()
    print(f"[+] Block Size: {size}")
    
    offset = calculate_offset(size)
    print(f"[+] Offset: {offset}")

    print("\n--- Recovering Secret ---")
    full_secret = ""
    # Loops to recover the entire secret character by character
    for i in range(64): 
        next_char = brute_force_next_byte(size, offset, full_secret)
        if next_char:
            full_secret += next_char
            print(f"Current Progress: {full_secret}")
            if next_char == "}": 
                break
        else:
            print("[!] No more characters detected.")
            break

    print(f"\n[FINAL SECRET]: {full_secret}")
