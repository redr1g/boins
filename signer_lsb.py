from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from PIL import Image
import numpy as np

# Function to convert signature to binary format
def encode_signature(signature):
    return ''.join(format(byte, '08b') for byte in signature)

# Function to hide signature in the least significant bits of pixels
def hide_signature_in_image(image_path, signature, output_path):
    # Load image
    img = Image.open(image_path)
    img = img.convert("RGB")  # Ensure image is in RGB format
    img_array = np.array(img)

    # Convert signature to binary
    signature_bits = encode_signature(signature)
    total_pixels = img_array.shape[0] * img_array.shape[1]
    
    # Add signature length at the beginning to know how many bits to extract later
    sig_length = len(signature_bits)
    sig_length_binary = format(sig_length, '032b')  # 32-bit binary representation of length
    full_data = sig_length_binary + signature_bits
    
    if len(full_data) > total_pixels * 3:  # 3 colors (RGB) for each pixel
        raise ValueError("Image too small to store the signature")

    # Flatten the image array to make it easier to work with
    flat_img = img_array.reshape(-1, 3)
    
    # Modify pixels
    for idx, bit in enumerate(full_data):
        if idx >= len(flat_img) * 3:
            break
            
        pixel_idx = idx // 3
        color_idx = idx % 3
        
        # Set the least significant bit to match our data bit
        flat_img[pixel_idx][color_idx] = (flat_img[pixel_idx][color_idx] & ~1) | int(bit)

    # Reshape back to original dimensions
    modified_img_array = flat_img.reshape(img_array.shape)
    
    # Save image with signature
    output_img = Image.fromarray(modified_img_array)
    output_img.save(output_path, format="PNG")  # Use PNG to avoid compression artifacts

    print(f"Image signed and saved to {output_path}")
    print(f"Embedded {len(full_data)} bits of data")

def sign_image(image_path, private_key_path, output_path):
    # Load private key
    with open(private_key_path, "rb") as key_file:
        private_key = RSA.import_key(key_file.read())
    
    # Load image
    img = Image.open(image_path).convert("RGB")
    
    # Important: Clear all LSBs before hashing for signing
    img_array = np.array(img)
    flat_img = img_array.reshape(-1, 3)
    for i in range(len(flat_img)):
        for j in range(3):  # RGB channels
            flat_img[i][j] &= ~1  # Clear LSB
    
    clean_img = Image.fromarray(flat_img.reshape(img_array.shape))
    img_bytes = clean_img.tobytes()

    # Hash the clean image
    hash_obj = SHA256.new(img_bytes)

    # Sign the hash
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    
    print(f"Signature size: {len(signature)} bytes")
    print("Image size:", img.size)
    print("Image mode:", img.mode)
    print("Hash:", hash_obj.hexdigest())

    # Hide signature in the original image (not the cleaned one)
    hide_signature_in_image(image_path, signature, output_path)

if __name__ == "__main__":
    # Generate keys (one-time setup)
    # key = RSA.generate(4096)
    # with open("private_key.pem", "wb") as f:
    #     f.write(key.export_key('PEM'))
    # with open("public_key.pem", "wb") as f:
    #     f.write(key.publickey().export_key('PEM'))
    
    # Sign an image
    sign_image("original.png", "private_key.pem", "signed.png")
