# file_recovery.py

import os
import shutil
import logging

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('file_recovery.log')
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

def recover_file(file_path, backup_dir):
    """
    Recovers a file from a backup directory if it is missing at the target location.
    
    :param file_path: The expected path of the file.
    :param backup_dir: Directory containing backup copies.
    :return: The path of the recovered file if successful, else None.
    """
    try:
        if os.path.exists(file_path):
            logger.info(f"File '{file_path}' already exists. No recovery needed.")
            return file_path
        else:
            # Construct the backup file path using the same filename.
            backup_file = os.path.join(backup_dir, os.path.basename(file_path))
            if os.path.exists(backup_file):
                shutil.copy(backup_file, file_path)
                logger.info(f"Recovered file from '{backup_file}' to '{file_path}'.")
                return file_path
            else:
                logger.error(f"Backup file not found: '{backup_file}'.")
                return None
    except Exception as e:
        logger.exception(f"Error recovering file '{file_path}': {e}")
        return None

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Recover a file from a backup directory.")
    parser.add_argument("file_path", help="Path of the file to recover.")
    parser.add_argument("backup_dir", help="Directory where backups are stored.")
    args = parser.parse_args()

    recovered = recover_file(args.file_path, args.backup_dir)
    if recovered:
        print(f"File recovered at: {recovered}")
    else:
        print("File recovery failed.")
