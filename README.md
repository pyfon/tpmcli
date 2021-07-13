# Team Password Manager CLI Client
This is a simple command-line client for [Team Password Manager](https://teampasswordmanager.com/) written in Python 3.  
The software takes advantage of the TPM API - the API feature must be enabled on your target server.  
The tool can query TPM for passwords using search patterns. It has built-in regular expression functionality, and aims to be as fast as possible by utilising caching and concurrency.
This is third-party and unofficial software - Team Password Manager does not provide a command-line client themselves.  
This is free software and is released under the GPLv3.  

## Installation
The following is a rough installation guide, but please adjust to your environment and requirements:  
1. Install needed libraries:  
`pip3 install pygments requests`
2. Create the .tpm directory:  
`mkdir ~/.tpm`
3. Copy the configuration file:  
`cp settings.ini ~/.tpm/`
4. Configure TPM:  
`vi ~/.tpm/settings.ini`
5. Copy tpm.py into your $PATH:  
`cp tpm.py ~/.local/bin/tpm && chmod a+x ~/.local/bin/tpm`  
**OR**  
`cp tpm.py /usr/bin/tpm && chmod a+x /usr/bin/tpm`
6. Generate the cache:  
`tpm --refresh`

## Usage
The available options can be seen with --help:  

    $ ./tpm.py --help
    usage: tpm.py [-h] [--user USER] [--password PASSWORD] [--url URL] [--allfields] [--regex] [--threads THREADS] [--refresh] [--nocolor] [--brief] [pattern ...]
    
    Get passwords from Team Password Manager.
    
    positional arguments:
      pattern
    
    optional arguments:
      -h, --help            show this help message and exit
      --user USER, -u USER  TPM user to authenticate as
      --password PASSWORD, -p PASSWORD
                            TPM password for authentication
      --url URL, -l URL     TPM API URL
      --allfields, -a       Print all TPM record fields
      --regex, -r           Interpret PATTERNS as Perl-compatible regular expressions (PCREs).
      --threads THREADS, -t THREADS
                            Maximum number of workers for concurrent API calls. Default: 16
      --refresh             Update the TPM cache and quit
      --nocolor             Do not use colourized output
      --brief               Print a simpler, brief output

**Important:** The TPM cache must be periodically be re-generated with `--refresh`.  
New passwords will not appear in queries until they have been added to the cache.  
You may consider using cron to refresh the cache automatically.

### Examples
    $ tpm --brief searchterm anothersearchterm
    Found 3 results...
    name: Website
    username: web1
    password: pass345
    ---
    name: Site2
    username: user1
    password: password1
    ---
    name: Another password
    username: somecompany
    password: pw455653%
    ---

    $ tpm --regex '^websites?$'
    {'access_info': 'ssh://root@site',
     'email': '',
     'name': 'Website2 Password',
     'notes': 'Notes notes notes'
     'password': 'password123',
     'project': 'My Project',
     'updated_by': 'Some Guy',
     'updated_on': '2021-02-02 11:21:38',
     'username': 'root'}
