# CSI

Proof-of-concept (PoC) implementation of Consent Injection. Used to demonstrate the posibility to automate injection of consent strings in a browser using Selenium Webdriver, to assess compliance with the Transparency & Consent Framework (TCF) version 2.2.

Based on previous work by [C Lendering](https://github.com/CLendering/IAB-vendor-compliance). Thesis with research performed with this PoC will be made available later.

# Installation

`sudo apt update`

`sudo apt install python3-pip python3-dnspython python3-selenium python3-pynput npm`

`npm install -g @iabtechlabtcf/cli`

`git clone https://github.com/dirkdonkers/CSI.git`

# Usage

```
usage: Consent Injecter [-h] [-u URL] [-l LIST] [-d] [-v] [-s] [-o OUTPUT]
                        [--detectOnly] [--language LANGUAGE] [-t THREADS]

options:
  -h, --help            show this help message and exit
  -u URL, --url URL
  -l LIST, --list LIST
  -d, --debug
  -v, --verbose
  -s, --screenshot
  -o OUTPUT, --output OUTPUT
  --detectOnly
  --language LANGUAGE
  -t THREADS, --threads THREADS
```

## Single URL Example

`python3 main.py -u <domain> -v -o <output_file>`

## File with URLs Example

`python3 main.py -l <file> --lang en,fr,de --th 6 -s`

## Interaction

During run of script it can be aborted by pressing **ESC** or it's status can be checked by pressing **Space**.
