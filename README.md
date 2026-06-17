# Networ Traffic Analyzer

![Python](https://img.shields.io/badge/python-%230db7ed.svg?style=for-the-badge&logo=python&logoColor=purple)

A Python-based network traffic analyzer built for learning purposes 
and practical application of network security concepts.

## Current Features
- Live TCP packet sniffing via PyShark
- Basic traffic analysis exported to CSV format

## Roadma
- TLS handshake inspection
- JA3/JA4 client fingerprinting for threat identification
- Extended protocol support

## Tech Stack
- Python 3.13
- PyShark (TShark wrapper)
- Developed on Windows — note: PyShark pipeline handling 
  on Windows requires workarounds

## How to Run
```bash
pip install pyshark
python main.py
```

## Notes
PyShark on Windows can be unstable due to pipeline management 
issues with TShark. If you encounter errors, running via WSL 
is a more stable alternative.
