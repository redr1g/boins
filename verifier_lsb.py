import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from PIL import Image

import numpy as np

def extract_signature(image_path):
    # Load image
    img = Image.open(image_path)
    img = img.convert("RGB")
    img_array = np.array(img)
    
    # Flatten the array
    flat_img = img_array.reshape(-1, 3)
    
    # First, extract the 32-bit length value
    length_bits = ""
    for i in range(32):
        pixel_idx = i // 3
        color_idx = i % 3
        length_bits += str(flat_img[pixel_idx][color_idx] & 1)
    
    sig_length = int(length_bits, 2)
    
    # Extract the signature bits
    signature_bits = ""
    for i in range(32, 32 + sig_length):
        if i >= len(flat_img) * 3:
            break
        pixel_idx = i // 3
        color_idx = i % 3
        signature_bits += str(flat_img[pixel_idx][color_idx] & 1)
    
    # Convert binary string back to bytes
    signature = bytearray()
    for i in range(0, len(signature_bits), 8):
        if i + 8 <= len(signature_bits):
            byte = int(signature_bits[i:i+8], 2)
            signature.append(byte)
    
    return bytes(signature)

def verify_image(image_path, signed_image_path, public_key_path):
    # Load public key
    with open(public_key_path, "rb") as key_file:
        public_key = RSA.import_key(key_file.read())
    
    # Extract signature from signed image
    signature = extract_signature(signed_image_path)
    
    # Load original image
    img = Image.open(image_path)
    img_bytes = img.tobytes()
    
    # Hash the original image
    hash_obj = SHA256.new(img_bytes)
    
    try:
        # Verify signature
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False
    
if __name__ == "__main__":
    # Verify the image and open it if verification is successful
    result = verify_image("original.png", "signed.png", "public_key.pem")
    if result:
        print("Verification result: Successful")
        os.startfile("signed.png")  # This will open the image using the default application
    else:
        print("Verification result: Failed")