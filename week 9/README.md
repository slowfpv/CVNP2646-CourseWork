# Week 9 - Patch Compliance Tracker

## Overview
This project is a patch compliance tracker for a 20-host environment. It loads host data from a JSON inventory, calculates days since each system was last patched, applies a point-based risk scoring algorithm, assigns risk levels, identifies high-risk hosts, and generates reports in JSON, text, and HTML format.

Patch management is important because unpatched systems are one of the most common attack vectors in security breaches. This project supports risk prioritization, compliance reporting, and automation.

## Usage
Run the program with:

```bash
python3 patch_tracker.py