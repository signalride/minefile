from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import os
import magic
import hashlib
import re
from collections import defaultdict
from io import BytesIO

# Initialize magic file type detector
file_magic = magic.Magic(mime=True)

SUPPORTED_TYPES = {
    # Documents
    'application/pdf': 'pdf',
    'application/msword': 'doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
    'application/vnd.ms-excel': 'xls',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
    'application/vnd.ms-powerpoint': 'ppt',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
    'application/vnd.oasis.opendocument.text': 'odt',
    'application/rtf': 'rtf',
    'text/csv': 'csv',

    # Images
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/bmp': 'bmp',
    'image/tiff': 'tiff',
    'image/webp': 'webp',
    
    # Archives
    'application/zip': 'zip',
    'application/x-rar-compressed': 'rar',
    'application/x-7z-compressed': '7z',
    'application/x-tar': 'tar',
    'application/gzip': 'gz',
    'application/x-bzip2': 'bz2',
    'application/x-xz': 'xz',
    
    # Media
    'audio/mpeg': 'mp3',
    'audio/wav': 'wav',
    'video/mp4': 'mp4',
    'video/x-msvideo': 'avi',
    'video/x-matroska': 'mkv',
    'video/quicktime': 'mov',
    
    # Executables
    'application/x-dosexec': 'exe',
    'application/x-msdownload': 'exe',
    'application/vnd.microsoft.portable-executable': 'exe',
    'application/x-executable': 'elf',
    'application/x-sharedlib': 'so',
    'application/x-mach-binary': 'mach-o',
    'application/x-shellscript': 'sh',
    
    # System Files
    'application/vnd.debian.binary-package': 'deb',
    'application/x-rpm': 'rpm',
    'application/x-msi': 'msi',
    
    # Development
    'text/x-python': 'py',
    'application/x-java-archive': 'jar',
    'application/javascript': 'js',
    'text/x-php': 'php',
    'text/html': 'html',
    'application/json': 'json',
    'application/xml': 'xml',
    
    # Certificates
    'application/x-pem-file': 'pem',
    'application/x-x509-ca-cert': 'crt',
    
    # Databases
    'application/x-sqlite3': 'db',
    
    # Virtualization
    'application/x-virtualbox-ova': 'ova',
    'application/x-virtualbox-vdi': 'vdi',
    
    # Miscellaneous
    'application/vnd.tcpdump.pcap': 'pcap',
    'application/x-bittorrent': 'torrent'
}


def validate_pdf(content):
    """Basic PDF validation using magic bytes and structure check"""
    try:
        # Check PDF header and footer
        if not content.startswith(b'%PDF-'):
            return False
        if b'%%EOF' not in content[-1024:]:  # Check last 1KB for EOF marker
            return False
        return True
    except:
        return False

def reassemble_tcp_stream(packets):
    sessions = packets.sessions()
    streams = defaultdict(bytes)
    
    for session in sessions:
        for pkt in sessions[session]:
            if TCP in pkt and Raw in pkt:
                streams[session] += bytes(pkt[Raw])
    return streams

def extract_files(pcap_file, output_dir="extracted_files/"):
    output_dir = output_dir + pcap_file.split("/")[-1].split(".")[0] + "/"
    os.makedirs(output_dir, exist_ok=True)
    file_count = defaultdict(int)
    unique_hashes = set()  # Track unique file hashes
    
    packets = rdpcap(pcap_file)
    streams = reassemble_tcp_stream(packets)
    
    for session, content in streams.items():
        if len(content) < 100:
            continue
            
        mime_type = file_magic.from_buffer(content)
        file_ext = SUPPORTED_TYPES.get(mime_type, None)
        
        if file_ext == 'pdf' and not validate_pdf(content):
            continue
            
        if file_ext:
            file_hash = hashlib.sha256(content).hexdigest()
            
            # Skip if we've already seen this exact content
            if file_hash in unique_hashes:
                continue
                
            unique_hashes.add(file_hash)
            short_hash = file_hash[:12]
            file_count[file_ext] += 1
            out_name = f"{short_hash}_{file_count[file_ext]}.{file_ext}"
            
            with open(os.path.join(output_dir, out_name), 'wb') as f:
                f.write(content)
            print(f"Extracted valid {file_ext.upper()} file: {out_name}")

import sys
if __name__ == "__main__":
    pcap_file = sys.argv[1]
    extract_files(pcap_file)
    print(f"\nExtraction complete. Valid files in: {os.path.abspath('extracted_files')}")
