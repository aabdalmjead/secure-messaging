from Crypto.Cipher import AES
import base64


def encrypt_with_aes_key(plain_text: str, aes_key: bytes) -> str:
   
    try:
        
        data = plain_text.encode("utf-8")

        
        cipher = AES.new(aes_key, AES.MODE_CFB)
        
        ciphertext = cipher.encrypt(data)
        
        
        result = cipher.iv + ciphertext
        return base64.b64encode(result).decode("utf-8")
        
    except Exception as e:
        print(f"Encryption error: {e}")
        return ""


def decrypt_with_aes_key(enc_text: str, aes_key: bytes) -> str:
    
    try:
        
        raw = base64.b64decode(enc_text.encode("utf-8"))

        
        iv = raw[:16]
        ciphertext = raw[16:]

        
        cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
        plain = cipher.decrypt(ciphertext)

        return plain.decode("utf-8")
        
    except Exception as e:
        print(f"Decryption error: {e}")
        return "[DECRYPTION FAILED]"



def test_aes():
    """Test the AES encryption and decryption"""
    print("Testing AES functions...")
    
   
    test_key = b"1234567890123456"  
    test_message = "Hello, secure world!"
    
    
    encrypted = encrypt_with_aes_key(test_message, test_key)
    print(f"Encrypted: {encrypted}")
    
    
    decrypted = decrypt_with_aes_key(encrypted, test_key)
    print(f"Decrypted: {decrypted}")
    
    
    if test_message == decrypted:
        print("AES test passed!")
    else:
        print("AES test failed!")


if __name__ == "__main__":
    test_aes()