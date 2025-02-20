#!/usr/bin/env python3
import argparse
import sys
import json

# Import functions from our modules.
from file_recovery import recover_file
from file_encryption import (
    sha256_encrypt_file,
    aes_encrypt_file,
    aes_decrypt_file,
    des_encrypt_file,
    des_decrypt_file,
)
from file_analyze import analyze_file

def main():
    """
    Main entry point for the production-level file tool.

    This tool provides three operations:
      1. File Recovery: Check if a file exists and, if missing, recover it from a backup directory.
      2. File Encryption/Decryption: Encrypt (or decrypt) a file using SHA256 (hash only), AES, or DES.
      3. File Analysis: Analyze a file to extract metadata such as size, timestamps, and MIME type.

    Usage Examples:
      Recover a file:
        python main.py recover /path/to/file.txt /path/to/backup_dir

      Generate SHA256 hash of a file:
        python main.py encrypt /path/to/file.txt --method sha256

      Encrypt a file using AES:
        python main.py encrypt /path/to/file.txt --method AES --key "thisisasecretkey123" --output /path/to/encrypted_file.aes.enc

      Decrypt an AES-encrypted file:
        python main.py encrypt /path/to/encrypted_file.aes.enc --action decrypt --method AES --key "thisisasecretkey123"

      Encrypt a file using DES:
        python main.py encrypt /path/to/file.txt --method DES --key "8bytekey" --output /path/to/encrypted_file.des.enc

      Decrypt a DES-encrypted file:
        python main.py encrypt /path/to/encrypted_file.des.enc --action decrypt --method DES --key "8bytekey"

      Analyze a file:
        python main.py analyze /path/to/file.txt
    """
    parser = argparse.ArgumentParser(
        description=(
            "Production Level File Tool\n\n"
            "This tool provides functionalities to recover missing files, perform encryption/decryption "
            "using SHA256 (hash), AES, or DES, and analyze file metadata.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Create subparsers for different commands.
    subparsers = parser.add_subparsers(
        title="subcommands",
        description="Choose one of the available commands",
        dest="command"
    )
    subparsers.required = True  # Force user to provide a subcommand.

    # Subparser for file recovery.
    recovery_parser = subparsers.add_parser(
        "recover",
        help="Recover a file from a backup directory if it is missing."
    )
    recovery_parser.add_argument("file_path", help="Path of the file to recover.")
    recovery_parser.add_argument("backup_dir", help="Directory containing backup copies of the file.")

    # Subparser for file encryption/decryption.
    encryption_parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt or decrypt a file using SHA256 (hash only), AES, or DES."
    )
    encryption_parser.add_argument("file_path", help="Path of the file to process.")
    encryption_parser.add_argument("--action", choices=["encrypt", "decrypt"], default="encrypt",
                                   help="Action to perform: 'encrypt' (default) or 'decrypt'.")
    encryption_parser.add_argument("--method", choices=["sha256", "AES", "DES"], required=True,
                                   help="Method to use. 'sha256' computes a hash (non-reversible); 'AES' and 'DES' support encryption and decryption.")
    encryption_parser.add_argument("--key", help="Encryption key (required for AES and DES).")
    encryption_parser.add_argument("--output", help="Optional output file path for the processed file.")

    # Subparser for file analysis.
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a file to extract metadata such as size, timestamps, and MIME type."
    )
    analyze_parser.add_argument("file_path", help="Path of the file to analyze.")

    # Parse arguments.
    args = parser.parse_args()

    # Process the subcommands.
    if args.command == "recover":
        recovered = recover_file(args.file_path, args.backup_dir)
        if recovered:
            print(f"File recovered at: {recovered}")
        else:
            print("File recovery failed. Check logs for details.")

    elif args.command == "encrypt":
        # Encryption/Decryption commands.
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
                sys.exit(1)
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
                sys.exit(1)
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

    elif args.command == "analyze":
        metadata = analyze_file(args.file_path)
        if metadata:
            print(json.dumps(metadata, indent=4))
        else:
            print("Error analyzing file. Check logs for details.")

if __name__ == "__main__":
    main()
