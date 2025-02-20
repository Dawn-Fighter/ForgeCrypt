# file_analyze.py

import os
import logging
import mimetypes
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('file_analyze.log')
fh.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

def analyze_file(file_path):
    """
    Analyzes the file and returns its metadata.
    
    :param file_path: Path of the file to analyze.
    :return: Dictionary containing metadata or None if an error occurs.
    """
    try:
        if not os.path.exists(file_path):
            logger.error(f"File '{file_path}' does not exist.")
            return None
        
        file_stats = os.stat(file_path)
        metadata = {
            'file_path': file_path,
            'size_bytes': file_stats.st_size,
            'created': datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(file_stats.st_atime).isoformat(),
        }
        # Determine MIME type (if possible)
        mime_type, _ = mimetypes.guess_type(file_path)
        metadata['mime_type'] = mime_type if mime_type else "unknown"

        logger.info(f"Metadata for '{file_path}' retrieved successfully.")
        return metadata
    except Exception as e:
        logger.exception(f"Error analyzing file '{file_path}': {e}")
        return None

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Analyze file metadata.")
    parser.add_argument("file_path", help="Path of the file to analyze.")
    args = parser.parse_args()

    metadata = analyze_file(args.file_path)
    if metadata:
        print(json.dumps(metadata, indent=4))
    else:
        print("Error analyzing file.")
