from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import base64


def generate_rsa_key_pair():
    
    try:
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    except Exception as e:
        print(f"Error generating RSA keys: {e}")
        return None, None


def encrypt_with_public_key(public_key_bytes, message: bytes) -> str:

    try:
        public_key = RSA.import_key(public_key_bytes)
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(message)
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return ""


def decrypt_with_private_key(private_key_bytes, encrypted_b64: str) -> bytes:
    
    try:
        private_key = RSA.import_key(private_key_bytes)
        cipher = PKCS1_OAEP.new(private_key)
        encrypted = base64.b64decode(encrypted_b64)
        return cipher.decrypt(encrypted)
    except Exception as e:
        print(f"Decryption error: {e}")
        return b""


def sign_message(private_key_bytes, message: bytes) -> str:

    try:
        key = RSA.import_key(private_key_bytes)
        h = SHA256.new(message)
        signature = pkcs1_15.new(key).sign(h)
        return base64.b64encode(signature).decode()
    except Exception as e:
        print(f"Signing error: {e}")
        return ""


def verify_signature(public_key_bytes, message: bytes, signature_b64: str) -> bool:
    
    try:
        key = RSA.import_key(public_key_bytes)
        h = SHA256.new(message)
        signature = base64.b64decode(signature_b64)
        pkcs1_15.new(key).verify(h, signature)
        return True
    except:
        return False



def test_rsa():
    
    print("Testing RSA functions...")
    
    
    private_key, public_key = generate_rsa_key_pair()
    if not private_key or not public_key:
        print("Key generation failed!")
        return
        
    print("Keys generated successfully")
    
    
    test_message = b"This is a secret AES key123"
    
    
    encrypted = encrypt_with_public_key(public_key, test_message)
    if not encrypted:
        print("Encryption failed!")
        return
        
    print("Message encrypted successfully")
    
    decrypted = decrypt_with_private_key(private_key, encrypted)
    if decrypted == test_message:
        print("Decryption successful - message matches!")
    else:
        print("Decryption failed - message doesn't match!")
        return
    
    
    signature = sign_message(private_key, test_message)
    if not signature:
        print("Signing failed!")
        return
        
    print("Message signed successfully")
    
    
    if verify_signature(public_key, test_message, signature):
        print("Signature verification successful!")
    else:
        print("Signature verification failed!")
        return
    
    
    wrong_signature = signature[:-10] + "aaaa"  
    if not verify_signature(public_key, test_message, wrong_signature):
        print("Wrong signature correctly rejected!")
    else:
        print("Wrong signature was accepted!")
        return
    
    print("\nAll RSA tests passed! Your crypto functions are working correctly.")


if __name__ == "__main__":
    test_rsa()