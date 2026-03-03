# CVNP2646 Week 6 - Authentication Log Scanner

## Title and Description
This project is a Python Authentication Log Scanner that parses authentication logs in key=value format, detects potential brute force activity, and generates SOC-friendly intelligence reports. It counts failed login attempts per user (targeted accounts) and per IP address (attack sources).

## Usage Instructions
Run the scanner from the week6 folder:

```bash
python auth_scanner.py auth_test.log