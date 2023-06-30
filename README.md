# PE_Potato

![ pe1 ](/assets/_1.png)
![ pe3 ](/assets/_2.png)
![ pe3 ](/assets/_3.png)

PE_Potato is a PE/ELF binary analyzer.

As the project as still very early in development, it does offer very basic functionaility.
However, this will change over time.

## Features
- View exported functions
- View imported functions
- View libraries
- View sections
- View the DOS header
- View the file header
- View the COFF header
- View Directories
- Query Virus Total for:
  - General information
  - Sections
  - AV Detections
  - Binary Names
  - Imports
  - Exports
  - Compiler Products
  - Yara Rules
  - Tags
  - HTTP Conversations
  - IP Traffic
  - Contained Resources
  - Contained Resources By Type
- Query Virus Total via:
  - Generated Hash
  - Manually Entered Hash
- Query Malware Bazaar via:
  - Hash (MD5, SHA1, SHA256)
  - File type
  - Tag
  - Signature
  - Recent malware samples (100 most recent samples or samples added in the last hour)
- Malware Bazaar raw json responses

## Planned features
- A modern GUI
- Elf parsing support
- View strings
- View debug info
- View the manifest
- View version info
- Query Virus Total for:
  - Basic Propeties
  - History
  - Pe Header
  - Contained Resources By Language
  - Mitre Attack TTP's
  - DNS lookups
  - Sigma Rules
  - Written and dropped files
  - Set registry keys
  - Process Tree
  - Other malicious payload information
- Upload samples to Virus Total
- Malware Bazaar:
  - Download individual samples
  - Download samples in bulk
  - Generate file hashes from disk
  - Query yara rules
  - Query sanbox intel