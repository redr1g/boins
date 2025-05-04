import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from PIL import Image

import numpy as np

def extract_signature_from_image(image_path):
    img = Image.open(image_path)
    img_array = np.array(img)
    flat_img = img_array.reshape(-1, 3)

    # Extract length first (32 bits)
    length_bits = ""
    for i in range(32):
        pixel_idx = i // 3
        color_idx = i % 3
        length_bits += str(flat_img[pixel_idx][color_idx] & 1)

    sig_length = int(length_bits, 2)

    # Extract signature bits
    signature_bits = ""
    for i in range(32, 32 + sig_length):
        if i >= len(flat_img) * 3:
            break
        pixel_idx = i // 3
        color_idx = i % 3
        signature_bits += str(flat_img[pixel_idx][color_idx] & 1)

    # Convert bits back to bytes
    signature = bytearray()
    for i in range(0, len(signature_bits), 8):
        if i + 8 <= len(signature_bits):  # Make sure we have a full byte
            byte = int(signature_bits[i:i+8], 2)
            signature.append(byte)

    return bytes(signature)

def verify_image(signed_image_path, public_key_path):
    # Load public key
    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())

    # Extract signature
    signature = extract_signature_from_image(signed_image_path)
    
    # Load the image and clear all LSBs for hashing
    img = Image.open(signed_image_path).convert("RGB")
    img_array = np.array(img)
    flat_img = img_array.reshape(-1, 3).copy()
    
    # Clear all LSBs (this is key for correct verification)
    for i in range(len(flat_img)):
        for j in range(3):  # RGB channels
            flat_img[i][j] &= ~1  # Clear LSB
    
    # Create clean image for hashing
    clean_img = Image.fromarray(flat_img.reshape(img_array.shape))
    img_bytes = clean_img.tobytes()
    
    # Hash the image with cleared LSBs
    hash_obj = SHA256.new(img_bytes)

    print("Signature length:", len(signature))
    print("Image size:", img.size)
    print("Image mode:", img.mode)
    print("Hash:", hash_obj.hexdigest())

    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        print("Verification result: ✅ Successful")
        return True, clean_img
    except (ValueError, TypeError) as e:
        print(f"Verification result: ❌ Failed - {str(e)}")
        return False, clean_img
    
if __name__ == "__main__":
    # Verify the image and open it if verification is successful
    success, result = verify_image("signed.png", "public_key.pem")
    if success:
        result.save("verified_image.png")
        os.startfile("verified_image.png")
        print("Verified image saved as 'verified_image.png'")