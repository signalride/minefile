from scapy.all import *
from scapy.layers.http import HTTPRequest, HTTPResponse
import os
import magic
import hashlib
import re
from collections import defaultdict
from io import BytesIO
import sys
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
    'application/vnd.oasis.opendocument.spreadsheet': 'ods',
    'application/vnd.oasis.opendocument.presentation': 'odp',
    'application/vnd.oasis.opendocument.graphics': 'odg',
    'application/rtf': 'rtf',
    'text/csv': 'csv',
    'application/vnd.amazon.ebook': 'azw',
    'application/epub+zip': 'epub',
    'application/x-mobipocket-ebook': 'mobi',
    'text/markdown': 'md',
    'application/vnd.apple.pages': 'pages',
    'application/vnd.apple.numbers': 'numbers',
    'application/vnd.apple.keynote': 'key',
    'application/x-abiword': 'abw',

    # Images
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/bmp': 'bmp',
    'image/tiff': 'tiff',
    'image/webp': 'webp',
    'image/svg+xml': 'svg',
    'image/heic': 'heic',
    'image/heif': 'heif',
    'image/x-icon': 'ico',
    'image/vnd.adobe.photoshop': 'psd',
    'image/x-eps': 'eps',
    'image/x-xcf': 'xcf',
    'image/x-canon-cr2': 'cr2',
    'image/x-nikon-nef': 'nef',
    'image/x-panasonic-raw': 'rw2',
    'image/x-fuji-raf': 'raf',
    'image/x-dcraw': 'raw',
    'image/x-djvu': 'djvu',
    
    # Archives
    'application/zip': 'zip',
    'application/x-rar-compressed': 'rar',
    'application/x-7z-compressed': '7z',
    'application/x-tar': 'tar',
    'application/gzip': 'gz',
    'application/x-bzip2': 'bz2',
    'application/x-xz': 'xz',
    'application/x-lzh-compressed': 'lzh',
    'application/x-cpio': 'cpio',
    'application/x-shar': 'shar',
    'application/x-iso9660-image': 'iso',
    'application/vnd.android.package-archive': 'apk',
    'application/x-apple-diskimage': 'dmg',
    'application/x-debian-package': 'deb',
    'application/x-redhat-package-manager': 'rpm',
    'application/x-msi': 'msi',
    
    # Media
    # Audio
    'audio/mpeg': 'mp3',
    'audio/wav': 'wav',
    'audio/aac': 'aac',
    'audio/ogg': 'ogg',
    'audio/flac': 'flac',
    'audio/x-m4a': 'm4a',
    'audio/x-ms-wma': 'wma',
    'audio/webm': 'weba',
    
    # Video
    'video/mp4': 'mp4',
    'video/x-msvideo': 'avi',
    'video/x-matroska': 'mkv',
    'video/quicktime': 'mov',
    'video/x-flv': 'flv',
    'video/x-ms-wmv': 'wmv',
    'video/mpeg': 'mpeg',
    'video/webm': 'webm',
    'video/3gpp': '3gp',
    'video/x-m4v': 'm4v',
    
    # Executables
    'application/x-dosexec': 'exe',
    'application/x-msdownload': 'exe',
    'application/vnd.microsoft.portable-executable': 'exe',
    'application/x-executable': 'elf',
    'application/x-sharedlib': 'so',
    'application/x-mach-binary': 'mach-o',
    'application/x-shellscript': 'sh',
    'application/x-msdos-program': 'com',
    'application/x-nintendo-nes-rom': 'nes',
    'application/x-sms-rom': 'sms',
    
    # System Files
    'application/vnd.debian.binary-package': 'deb',
    'application/x-rpm': 'rpm',
    'application/x-msi': 'msi',
    'application/x-apple-diskimage': 'dmg',
    'application/vnd.ms-cab-compressed': 'cab',
    'application/x-xar': 'pkg',
    'application/vnd.symbian.install': 'sis',
    
    # Development
    'text/x-python': 'py',
    'application/x-java-archive': 'jar',
    'application/javascript': 'js',
    'text/x-php': 'php',
    'text/html': 'html',
    'application/json': 'json',
    'application/xml': 'xml',
    'text/x-c': 'c',
    'text/x-c++': 'cpp',
    'text/x-csharp': 'cs',
    'text/x-ruby': 'rb',
    'text/x-perl': 'pl',
    'text/x-swift': 'swift',
    'text/x-go': 'go',
    'text/x-rust': 'rs',
    'application/typescript': 'ts',
    'text/x-scala': 'scala',
    'text/x-kotlin': 'kt',
    'text/x-lua': 'lua',
    'text/x-haskell': 'hs',
    'application/ld+json': 'jsonld',
    'text/css': 'css',
    'text/x-sass': 'sass',
    'text/x-less': 'less',
    'text/x-java': 'java',
    'application/x-httpd-php': 'php',
    'application/x-yaml': 'yaml',
    
    # Certificates
    'application/x-pem-file': 'pem',
    'application/x-x509-ca-cert': 'crt',
    'application/pkix-cert': 'cer',
    'application/pkcs12': 'p12',
    'application/x-pkcs12': 'pfx',
    'application/x-der': 'der',
    
    # Databases
    'application/x-sqlite3': 'db',
    'application/x-mdb': 'mdb',
    'application/x-msaccess': 'accdb',
    'application/x-dbf': 'dbf',
    'application/x-sql': 'sql',
    'application/bson': 'bson',
    
    # Virtualization/Cloud
    'application/x-virtualbox-ova': 'ova',
    'application/x-virtualbox-vdi': 'vdi',
    'application/x-vmdk': 'vmdk',
    'application/x-qcow2': 'qcow2',
    'application/x-ovf': 'ovf',
    'application/x-vhd': 'vhd',
    
    # Email
    'message/rfc822': 'eml',
    'application/vnd.ms-outlook': 'pst',
    'application/vnd.apple.mail': 'emlx',
    'application/mbox': 'mbox',
    
    # Fonts
    'font/ttf': 'ttf',
    'font/otf': 'otf',
    'font/woff': 'woff',
    'font/woff2': 'woff2',
    
    # 3D/CAD
    'model/stl': 'stl',
    'model/obj': 'obj',
    'model/x3d+xml': 'x3d',
    'application/sla': 'stl',
    'image/vnd.dwg': 'dwg',
    'application/dxf': 'dxf',
    'application/x-step': 'step',
    
    # Scientific
    'application/x-hdf': 'hdf5',
    'application/fits': 'fits',
    'application/x-root': 'root',
    'chemical/x-pdb': 'pdb',
    
    # GIS
    'application/vnd.google-earth.kml+xml': 'kml',
    'application/geo+json': 'geojson',
    'application/x-shapefile': 'shp',
    'image/x-geotiff': 'geotiff',
    
    # Miscellaneous
    'application/vnd.tcpdump.pcap': 'pcap',
    'application/x-bittorrent': 'torrent',
    'application/vnd.ms-fontobject': 'eot',
    'application/x-tex': 'tex',
    'text/calendar': 'ics',
    'application/vnd.visio': 'vsd',
    'application/x-mie': 'mie',
    'application/x-asar': 'asar',
    'application/x-nzb': 'nzb',
    'application/x-cbr': 'cbr',
    'application/x-cbz': 'cbz'
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
def extract_files(pcap_file, output_dir="extracted_files/", extensions=None):
    pcap_base = os.path.splitext(os.path.basename(pcap_file))[0]
    output_dir = os.path.join(output_dir, pcap_base) + "/"
    os.makedirs(output_dir, exist_ok=True)
    file_count = defaultdict(int)
    unique_hashes = set()
    
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
            if extensions is not None and file_ext not in extensions:
                continue
            file_hash = hashlib.sha256(content).hexdigest()
            
            if file_hash in unique_hashes:
                continue
                
            unique_hashes.add(file_hash)
            short_hash = file_hash[:12]
            file_count[file_ext] += 1
            out_name = f"{short_hash}_{file_count[file_ext]}.{file_ext}"
            
            with open(os.path.join(output_dir, out_name), 'wb') as f:
                f.write(content)
            print(f"Extracted valid {file_ext.upper()} file: {out_name}")
    
    return sum(file_count.values()), output_dir  # Return count and output directory

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <pcap_file> [extensions...]")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    selected_extensions = None
    
    if len(sys.argv) > 2:
        exts_input = [ext.lstrip('.').lower() for ext in sys.argv[2:]]
        valid_exts = []
        invalid_exts = []
        
        for ext in exts_input:
            if ext in SUPPORTED_TYPES.values():
                valid_exts.append(ext)
            else:
                invalid_exts.append(ext)
        
        invalid_exts = list(set(invalid_exts))
        valid_exts = list(set(valid_exts))
        
        if invalid_exts:
            print(f"Error: Invalid extensions detected: {', '.join(invalid_exts)}")
            print("Supported extensions: " + ", ".join(sorted(set(SUPPORTED_TYPES.values()))))
            sys.exit(1)
        
        selected_extensions = valid_exts if valid_exts else None
    
    extracted_count, output_dir = extract_files(pcap_file, extensions=selected_extensions)
    
    if extracted_count == 0:
        print("\nNo files were extracted from the PCAP.")
        sys.exit(1)
    else:
        print(f"\nExtraction complete. {extracted_count} files extracted to: {os.path.abspath(output_dir)}")
