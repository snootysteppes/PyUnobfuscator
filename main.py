import os
import re
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from os import system

def read_encrypted_file(file_path):
    """Read the contents of an encrypted Python file."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    
    with open(file_path, 'r') as f:
        encrypted_code = f.read().strip()
    return encrypted_code

def find_key_and_iv(encrypted_code):
    """Locate key and IV from the encrypted code."""
    key_pattern = re.compile(r'(?<=key\s*=\s*)(b"[^"]+"|\'[^\']+\')')
    iv_pattern = re.compile(r'(?<=iv\s*=\s*)(b"[^"]+"|\'[^\']+\')')

    key_match = key_pattern.search(encrypted_code)
    iv_match = iv_pattern.search(encrypted_code)

    if not key_match or not iv_match:
        raise ValueError("Key and/or IV not found in the encrypted code.")

    key = eval(key_match.group(0))  # Consider using ast.literal_eval for safety
    iv = eval(iv_match.group(0))    # Consider using ast.literal_eval for safety

    return key, iv

def detect_and_unobfuscate(file_path):
    """Detect encryption method (currently AES via PyCryptodome) and unobfuscate."""
    try:
        encrypted_code_b64 = read_encrypted_file(file_path)
        encrypted_code = base64.b64decode(encrypted_code_b64)

        key, iv = find_key_and_iv(encrypted_code_b64)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_code = unpad(cipher.decrypt(encrypted_code), AES.block_size)

        original_code = decrypted_code.decode('utf-8')
        print(f"Unobfuscated code:\n{original_code}")
        return original_code

    except Exception as e:
        print(f"Error during unobfuscation: {str(e)}")
        return None

def main():
    print("""
                                                                                  
 _____     _____         _   ___                 _                  ___     ___ 
|  _  |_ _|  |  |___ ___| |_|  _|_ _ ___ ___ ___| |_ ___ ___    _ _|_  |   |   |
|   __| | |  |  |   | . | . |  _| | |_ -|  _| .'|  _| . |  _|  | | |_| |_ _| | |
|__|  |_  |_____|_|_|___|___|_| |___|___|___|__,|_| |___|_|     \_/|_____|_|___|
      |___|                                                                     
  """)
    system("title " + "unobfuscator | @snootysteppes")
    
    encrypted_file_path = input("Enter the path to the encrypted Python file: ")
    
    if not os.path.isfile(encrypted_file_path):
        print("Invalid file path. Please try again. A file path should be like this: C:/Users/username/Desktop/file.py")
        return
    
    unobfuscated_code = detect_and_unobfuscate(encrypted_file_path)

    if unobfuscated_code:
        output_file_path = "unobfuscated_script.py"
        with open(output_file_path, "w") as f:
            f.write(unobfuscated_code)
        print(f"Unobfuscated code saved to {output_file_path}")

if __name__ == "__main__":
    main()

