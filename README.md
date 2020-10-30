
# ADFSpray

ADFSpray is a python3 tool to perform password spray attack against Microsoft ADFS.
ALWAYS VERIFY THE LOCKOUT POLICY TO PREVENT LOCKING USERS.


## How to use it
First, install the needed dependencies:
```
pip3 install -r requirements.txt
```
Run the tool with the needed flags:
```
usage: ./ADFSpray.py [-h] (-U USERLIST | -u USER  -p PASSWORD | -P PASSWORDLIST) [-t TARGET] [-o OUTPUT] [-V] [--threads THREADS]
```

## Options to consider
```
  -h, --help            show this help message and exit
  -U USERLIST, --userlist USERLIST
                        emails list to use, one email per line
  -u USER, --user USER  Single email to test
  -p PASSWORD, --password PASSWORD
                        Single password to test
  -P PASSWORDLIST, --passwordlist PASSWORDLIST
                        Password list to test, one password per line
  -t TARGET, --target TARGET
                        Target server to authenticate against
  -o OUTPUT, --output OUTPUT
                        Output each attempt result to a csv file
  -V, --verbose         Turn on verbosity to show failed attempts
  --threads THREADS     Number of threads
```

### Credit
https://github.com/xFreed0m/ADFSpray

### Issues, bugs and other code-issues
Just a custom modification
