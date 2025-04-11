# minefile
Extract all files within an pcap file
### SUPPORTED_TYPES
;;;
{
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
;;;
