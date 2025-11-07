# CSI

Proof-of-concept implementation of Consent Injection. Used to demonstrate the posibility to automate injection of consent strings in a browser using Selenium Webdriver, to assess compliance with the Transparency & Consent Framework (TCF) version 2.2.

Based on previous work by [C Lendering](https://github.com/CLendering/IAB-vendor-compliance). 

# Installation

`sudo apt update`

`sudo apt install python3-pip python3-dnspython python3-selenium python3-pynput npm`

`sudo npm install -g @iabtechlabtcf/cli`

`git clone https://github.com/dirkdonkers/CSI.git`

# Usage

```
usage: main.py [-h] [-u URL] [-l LIST] [-d] [-v] [-s] [-o OUTPUT] [--detectOnly] [--language LANGUAGE] [-t THREADS]

Proof-of-concept script to detect implementations of the Transparency and Consent Framework (TCF), and to assess compliance with it's specification

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL of single website to test.
  -l LIST, --list LIST  name of file with websites to test, one on each line.
  -d, --debug           show debug output in console.
  -v, --verbose         show verbose output in console.
  -s, --screenshot      take screenshot of website when interaction with cookie dialog fails, usefull for finding new strings to search for in cookie
                        dialogs.
  -o OUTPUT, --output OUTPUT
                        file in which to store results.
  --detectOnly          only detect the implementation of the TCF on a website, perform no further assessment.
  --language LANGUAGE   language(s) of cookie dialogs to look for, in a comma-separated list. Languages must be present in
                        ./resource_files/accept_strings.json file. Default is en,nl.
  -t THREADS, --threads THREADS
                        number of threads to use.
```

## Single URL Example

`python3 main.py -u <domain> -v -o <output_file>`

## File with URLs Example

`python3 main.py -l <file> --lang en,fr,de --th 6 -s`

## Interaction

During run of script it can be aborted by pressing **ESC** or it's status can be checked by pressing **Space**.
