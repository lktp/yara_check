 
Needs alot of work, just leaving here for now for storage.


Designed for running on linux, in theory should work on windows hasnt been tested

Designed to run lots of Yara rules, against lots of Malicious files,

will build a .txt report, as well as an html report.

Usage:

python yara_check.py -p <path to folder with malware> 

Options

-o no console output
-v Verbose logging
-r reset (not implemented at this time.)

Note:  I take no credit for the rules in the system, Most of them are from GITHUB and similar places.  They may be slightly modified for myself.
       The only thing I take credit for is the yara_check.py script., the rest is just the open source support files


Need to create the folders
html
logs
malware
reports

These will be created automatically later, they just havent been done yet.
