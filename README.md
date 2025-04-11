# minefile
Extract all files within an pcap file
```python
python3 main.py {file-name} {extension's} 
```

### eXample 
**No extension means all**
```bash
python3 main.py asd.pcap html pdf bmp
```


### SUPPORTED_TYPES
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


