# file_encryption.py

import os
import logging
import hashlib
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('file_encryption.log')
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

def pad(data, block_size):
    """
    Pads the data to a multiple of block_size using PKCS#7 padding.
    """
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length

def unpad(data):
    """
    Removes PKCS#7 padding.
    """
    padding_length = data[-1]
    return data[:-padding_length]

def sha256_encrypt_file(file_path):
    """
    Computes the SHA256 hash of the file's contents.
    
    :param file_path: Path to the file.
    :return: SHA256 hexadecimal digest or None if error.
    """
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        result = sha256_hash.hexdigest()
        logger.info(f"SHA256 hash for '{file_path}' computed successfully.")
        return result
    except Exception as e:
        logger.exception(f"Error computing SHA256 for '{file_path}': {e}")
        return None

def aes_encrypt_file(file_path, key, output_file=None):
    """
    Encrypts a file using AES encryption (CBC mode).
    
    :param file_path: Path of the file to encrypt.
    :param key: AES key (must be 16, 24, or 32 bytes).
    :param output_file: Optional output file path; if None, '.aes.enc' is appended.
    :return: The output file path if successful, else None.
    """
    try:
        if len(key) not in (16, 24, 32):
            logger.error("Invalid AES key length. Must be 16, 24, or 32 bytes.")
            return None

        with open(file_path, "rb") as f:
            data = f.read()
        
        block_size = AES.block_size  # typically 16 bytes
        data_padded = pad(data, block_size)
        iv = get_random_bytes(block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(data_padded)

        if output_file is None:
            output_file = file_path + ".aes.enc"

        with open(output_file, "wb") as out_file:
            out_file.write(iv + ciphertext)
        
        logger.info(f"AES encryption of '{file_path}' completed successfully. Output: '{output_file}'")
        return output_file
    except Exception as e:
        logger.exception(f"Error during AES encryption of '{file_path}': {e}")
        return None

def aes_decrypt_file(file_path, key, output_file=None):
    """
    Decrypts an AES-encrypted file.
    
    :param file_path: Path of the encrypted file.
    :param key: AES key (must be 16, 24, or 32 bytes).
    :param output_file: Optional output file path; if None, original file name is restored.
    :return: The output file path if successful, else None.
    """
    try:
        if len(key) not in (16, 24, 32):
            logger.error("Invalid AES key length. Must be 16, 24, or 32 bytes.")
            return None
        
        block_size = AES.block_size
        with open(file_path, "rb") as f:
            file_data = f.read()
        iv = file_data[:block_size]
        ciphertext = file_data[block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded)

        if output_file is None:
            # Remove .aes.enc if present; otherwise append .dec
            if file_path.endswith(".aes.enc"):
                output_file = file_path[:-8]
            else:
                output_file = file_path + ".dec"

        with open(output_file, "wb") as out_file:
            out_file.write(decrypted)
        
        logger.info(f"AES decryption of '{file_path}' completed successfully. Output: '{output_file}'")
        return output_file
    except Exception as e:
        logger.exception(f"Error during AES decryption of '{file_path}': {e}")
        return None

def des_encrypt_file(file_path, key, output_file=None):
    """
    Encrypts a file using DES encryption (CBC mode).
    
    :param file_path: Path of the file to encrypt.
    :param key: DES key (must be exactly 8 bytes).
    :param output_file: Optional output file path; if None, '.des.enc' is appended.
    :return: The output file path if successful, else None.
    """
    try:
        if len(key) != 8:
            logger.error("Invalid DES key length. Must be 8 bytes.")
            return None

        with open(file_path, "rb") as f:
            data = f.read()

        block_size = DES.block_size  # typically 8 bytes
        data_padded = pad(data, block_size)
        iv = get_random_bytes(block_size)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(data_padded)

        if output_file is None:
            output_file = file_path + ".des.enc"

        with open(output_file, "wb") as out_file:
            out_file.write(iv + ciphertext)

        logger.info(f"DES encryption of '{file_path}' completed successfully. Output: '{output_file}'")
        return output_file
    except Exception as e:
        logger.exception(f"Error during DES encryption of '{file_path}': {e}")
        return None

def des_decrypt_file(file_path, key, output_file=None):
    """
    Decrypts a DES-encrypted file.
    
    :param file_path: Path of the encrypted file.
    :param key: DES key (must be exactly 8 bytes).
    :param output_file: Optional output file path; if None, original file name is restored.
    :return: The output file path if successful, else None.
    """
    try:
        if len(key) != 8:
            logger.error("Invalid DES key length. Must be 8 bytes.")
            return None

        block_size = DES.block_size
        with open(file_path, "rb") as f:
            file_data = f.read()
        iv = file_data[:block_size]
        ciphertext = file_data[block_size:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted_padded)

        if output_file is None:
            if file_path.endswith(".des.enc"):
                output_file = file_path[:-8]
            else:
                output_file = file_path + ".dec"

        with open(output_file, "wb") as out_file:
            out_file.write(decrypted)
        
        logger.info(f"DES decryption of '{file_path}' completed successfully. Output: '{output_file}'")
        return output_file
    except Exception as e:
        logger.exception(f"Error during DES decryption of '{file_path}': {e}")
        return None

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Encrypt or Decrypt a file using various methods (sha256, AES, DES)."
    )
    parser.add_argument("file_path", help="Path of the file to process.")
    parser.add_argument("--action", choices=["encrypt", "decrypt"], default="encrypt",
                        help="Action to perform: 'encrypt' (default) or 'decrypt'.")
    parser.add_argument("--method", choices=["sha256", "AES", "DES"], required=True,
                        help="Method to use. 'sha256' computes a hash (encryption only); 'AES' and 'DES' support both encryption and decryption.")
    parser.add_argument("--key", help="Encryption key (required for AES and DES).")
    parser.add_argument("--output", help="Optional output file path.")
    args = parser.parse_args()

    if args.method == "sha256":
        if args.action == "decrypt":
            print("SHA256 is a hash function and cannot be decrypted.")
        else:
            result = sha256_encrypt_file(args.file_path)
            if result:
                print(f"SHA256 hash: {result}")
            else:
                print("Error computing SHA256 hash. Check logs for details.")
    elif args.method == "AES":
        if not args.key:
            print("AES encryption/decryption requires a key. Please provide one using --key.")
        else:
            key_bytes = args.key.encode()
            if args.action == "encrypt":
                output_file = aes_encrypt_file(args.file_path, key_bytes, args.output)
                if output_file:
                    print(f"AES encrypted file saved as: {output_file}")
                else:
                    print("Error during AES encryption. Check logs for details.")
            else:  # decrypt
                output_file = aes_decrypt_file(args.file_path, key_bytes, args.output)
                if output_file:
                    print(f"AES decrypted file saved as: {output_file}")
                else:
                    print("Error during AES decryption. Check logs for details.")
    elif args.method == "DES":
        if not args.key:
            print("DES encryption/decryption requires a key. Please provide one using --key.")
        else:
            key_bytes = args.key.encode()
            if args.action == "encrypt":
                output_file = des_encrypt_file(args.file_path, key_bytes, args.output)
                if output_file:
                    print(f"DES encrypted file saved as: {output_file}")
                else:
                    print("Error during DES encryption. Check logs for details.")
            else:  # decrypt
                output_file = des_decrypt_file(args.file_path, key_bytes, args.output)
                if output_file:
                    print(f"DES decrypted file saved as: {output_file}")
                else:
                    print("Error during DES decryption. Check logs for details.")
