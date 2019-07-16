# file-integrity-manager
File Integrity Manager. Addresses PCI requirement 11.5.

# Introduction

This document details how to setup and use the File Integrity Monitoring python script to monitor a directory and provide alerts if a file is modified or added.

There are three steps in setting up the File Integrity Monitor;
- Generate a file hash list
- Whitelist files that may change
- Run the FIM in monitor mode

The -h print help screen is shown below which lists the command line options for the File integrity checker, and also gives an example command line of a one pass hash check.


----
 File Integrity Checker version <1.2> Date:16th July 2019
------
  FIMChecker.py <options> <target dir name> OR FIMChecker.py <options>

  eg.

  FIMChecker.py -q 3 -n -c hashList.txt /git/src

 -- Commands --
   -g : Generate a hash list from the passed path.

   -c <check file name> : check the hashes of the target files

   -mm <n> : Monitor mode - Don't exit repeatedly check hashes. Sleep for
       n seconds.

   -i <filename and path> : Set the ignore file.

 -- Options --

   -q <n> : Level to output Debug string to std out (1 to 10).

   -l <n> : Level Log debug outtput to file.

   -o <output directory path> : Output directory to put files out to.              
		Try to create the output directory in the current directory.
		Otherwise the directory named will be written to.

   -m <n> : Set the maximum directory depth to traverse

   -n : Set no clobber mode, so output files will not be over written.

   -h : print this command line help.
---





# Initial Setup

### Baseline Hash List Creation


To use the File Integrity Checker a baseline hash list needs to be created. To create the hash list the **-g** command line option must be used. Note the current directory is git/. 
The example hashes the entire src directory structure. The script recurses through the entire directory structure.
An ignore file can also be included to force the script to ignore files or directories as indicated by the “.gitignore” file format.

Note the target email and password will need to be edited in the code. Search for the @ symbol in the code. This will be fixed in an update.


*$ python ~/git/FIMChecker.py -g path*

[+] Building Directory List. Please wait...

[+] Generating File Hashes

[+] Total Number of files: 1388

[+] Writing Hashes to output file

[+] Done!

And example using the **-i **option and the **.gitignore** file. Note the **-o **option is also used. 

The resultant hash file will be written to the directory indicated.
 
*python ~/git/FIMChecker.py -o ~/git/ -i .gitignore -g .*
 

Getting a directory listing shows a new file created **hashList.txt**. 

If the **-n **no clobber option switch is used the file will not be overwritten, a new file will be created appended with an integer up to 255.

$ ls
src				hashList.txt	

### The Hash List File



A line is added to the file for each file hashed. 
Directories are added but are not hashed.

Note each entry has 3 fields The first is a letter either **S (Scan)** or **I (Ignore)**.

S be233b91693a176c1f7169533f6dd45b src/Funding/Funding.php

S  src/WalletBundle/EventListener/Funding

S 8de7c6586cfe689ef5417997d70cb1ba src/EventListener/Subscriber.php

S  src/WalletBundle/EventListener/Withdrawal

S fcb4bf8f4e774dc3b64dba6cd1c8c8bc src/Event.php

S fe33aa3ee3c663c095cabaa570ce06412 src//Event/Event.php

S 874939edaa4da237cfac61fd4fdb1522 src/Exception.php

S ab841597061fa200d548ab84c917f7d1 src//Exception/Exception.php


***Files ignored, are ignored and not hashed or checked. ***

Ignoring files has the effect of whitelisting the file.

Files marked with an **S** are scanned and checked. 

An alert is raised if the hash does not match the existing file’s hash.
### White Listing Files

To white list a file, replace the default S character with an I character.


### Monitor Mode

The script will run in a polling monitor mode to provide fast detection of modified files.

To run the FIM in monitor mode. Use the -mm <n> command switch.

n is in seconds. 

For a 10 minute polling period is 600 seconds.

**For a 10 minute polling period use 600 not 20.**

The following command line shows the FIM script being run in monitor mode, with the resultant output. Note the** & **character at the end of the command line to run the script in the background.

Also note the previously generated hash list input as the** -c **parameter.

$ python ~/git/devops/fim_checker/FIMChecker.py -mm 20 -c hashList.txt directory_name &

[1] 11846

[+] Monitor Mode Sleep time set to: 20

[+] Building Directory List. Please wait...

[+] Reading Hashes from hashList.txt please wait....

[+] Checking Hashes...

[+] Total Number of files: 1388

[-] Filename: src/Event/Event.php

[-] Did Not find hash: fe33aa3ee3c663c095cabaa570ce0641 in hash list.

[-] Recorded Hash: fe33aa3ee3c663c095cabaa570ce06412

[-] File must be checked!

[+] Sending Email...

[+] Sleeping for 20 seconds...

### Email Alerts

An email alert will be raise and sent to the email address set in the code. The sender’s email is also needs to be set in the code.

A separate email will be generated for each hash mismatch, or new file detected.

Unknown File Detected

Detected File Details: 

FileName: git/doc/onboarding/malware.php, MD5 Hash: 1349ea365bba46f46925aa884df94490 
 
Error Message: Unknown File

Hash File Mismatch

File Integrity has been compromised.
 
Modified File Details:

FileName: git/src/Event/Event.php, MD5 Hash: fe33aa3ee3c663c095cabaa570ce06412 

 
Detected File Details:

FileName: git/src/Event/Event.php, MD5 Hash: fe33aa3ee3c663c095cabaa570ce0641 
 
Error Message: Hash Mismatch

### Monitoring

It is intended the File Integrity Monitor is used in production to monitor the integrity of the source code and web source that contains the website production code. 

The File Integrity Monitor will monitor the production website code and raise alerts if any of the files are modified or if new files are added.
