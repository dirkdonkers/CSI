from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import ElementClickInterceptedException
import time
import argparse
import os.path
import sys
import logging
import dns.resolver
from urllib.parse import urlparse
import json
from selenium.webdriver.common.by import By
import os
import datetime
import threading
from pynput import keyboard
import signal
from urllib.parse import unquote
from urllib.parse import quote_plus
import urllib.request
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.action_chains import ActionChains
import configparser

# Global variables

version = "0.0.7"
CONFIG_FILE = r"./config"

parser: argparse.ArgumentParser()
args: argparse.Namespace
TCSTRING_MAGIC_HEADER = ""
TCSTRING_REJECT_ALL = ""
TCSTRINGS = []
COMMON_TC_COOKIES = []
ACCEPT_STRINGS = []
STORAGE_DISCLOSURES = {}
STORAGE_DISCLOSURES = {}
TESTCASES = {}

# Global variables used as counters

count_TCF_detections = 0 
count_TCF_non_detections = 0
count_cookie_identifiers_detected = 0
total_tested = 0
errors = 0
filtered_out = 0
consent_before_interaction = 0
injected_string_not_returned = 0
failed_injection = 0
violating_purpose = 0
violating_vendor = 0
undisclosed_cookie = 0
vendor_not_in_gvl = 0

# Read main config file

configParser = configparser.ConfigParser()
configParser.read(CONFIG_FILE)

CMP_SPECIFICATION_FILE = configParser['Config files']['CMP_SPECIFICATION_FILE']
DNS_RESOLVERS_FILE = configParser['Config files']['DNS_RESOLVERS_FILE']
DIALOG_ACCEPT_STRINGS_FILE = configParser['Config files']['DIALOG_ACCEPT_STRINGS_FILE']
COMMON_TC_COOKIES_FILE = configParser['Config files']['COMMON_TC_COOKIES_FILE']
TESTCASES_FILE = configParser['Config files']['TESTCASES_FILE']

URL_ONLINE_ENCODER = configParser['Online resources']['URL_ONLINE_ENCODER']
URL_GVL = configParser['Online resources']['URL_GVL']

MAX_RETRIES = int(configParser['Run variables']['MAX_RETRIES'])
TIME_FACTOR = int(configParser['Run variables']['TIME_FACTOR'])

FALSE_INJECTION_POINTS = configParser['Consistent identifiers']['FALSE_INJECTION_POINTS']
IFRAME_IDENTIFIERS = configParser['Consistent identifiers']['IFRAME_IDENTIFIERS']


# Read other config files with known identifiers etc
with open(CMP_SPECIFICATION_FILE) as file:
    CMP_SPECIFICATION = json.load(file)

with open(DIALOG_ACCEPT_STRINGS_FILE) as file:
    DIALOG_ACCEPT_STRINGS = json.load(file)

with open(DNS_RESOLVERS_FILE) as file:
    DNS_RESOLVERS = json.load(file)

with open(COMMON_TC_COOKIES_FILE) as file:
    COMMON_TC_COOKIES_JSON = json.load(file)
    for CMP in COMMON_TC_COOKIES_JSON :
        COMMON_TC_COOKIES.append(CMP["cookie"])

try:
    with urllib.request.urlopen(URL_GVL) as url:
        GLOBAL_VENDOR_LIST = json.load(url)
except urllib.error.URLError :
    # First connection to internet, show error and exit if unsucessful
    print(f"[ERR] error retrieving GVL, do we have an internet connection?")
    exit(0)

with open(TESTCASES_FILE) as file:
    TESTCASES = json.load(file)


starttime = datetime.datetime.now()

'''
Function using Argument Parser to pase command line parameters and flags
'''
def parse_command() :
    global args
    parser = argparse.ArgumentParser(
                        prog='main.py',
                        description='Proof-of-concept script to detect \
                        implementations of the Transparency and Consent \
                        Framework (TCF), and to assess compliance with \
                        it\'s specification')
                        
    # Input options
    parser.add_argument('-u', '--url', help='URL of single website to test.')
    parser.add_argument('-l', '--list', help='name of file with websites to \
            test, one on each line.')
    
    # Output options
    parser.add_argument('-d', '--debug', action='store_true', help='show debug \
            output in console.')
    parser.add_argument('-v', '--verbose', action='store_true', help='show \
            verbose output in console.')
    parser.add_argument('-s', '--screenshot', action='store_true', help='take \
            screenshot of website when interaction with cookie dialog fails, \
            usefull for finding new strings to search for in cookie dialogs.')
    parser.add_argument('-o', '--output', help='file in which to store results.')
    
    # Mode options
    parser.add_argument('--detectOnly', action='store_true', help='only detect \
            the implementation of the TCF on a website, perform no further \
            assessment.')

    # Supported language(s) for accept all button detection, accepts comma 
    # separated list from (en,nl,etc..)
    parser.add_argument('--language', default="en,nl", help='language(s) of \
            cookie dialogs to look for, in a comma-separated list. Languages \
            must be present in ./resource_files/accept_strings.json file. \
            Default is en,nl.')

    parser.add_argument('-t', '--threads', default=3, help='number of threads \
            to use.')

    args = parser.parse_args()

    # TODO: (if verbose or debug) print version?

    if ( args.debug ) :
        print("[DEB] Enabling debug output.")
        print("[DEB] Parsing command")
        if ( args.verbose ) :
            print("[DEB] Verbose output is enabled")
        #verbosity
        if ( args.url != None ) :
            print(f"[DEB] URL read from input: {args.url}" )
        if ( args.list != None ) :
            print(f"[DEB] Reading URLs from input file: {args.list}" )
        if ( args.output != None ) :
            print(f"[DEB] saving output in file: {args.output}" )
        if ( args.screenshot ) :
            print(f"[DEB] saving screenshots when interaction with cookie dialog fails")
        if ( args.detectOnly ) :
            print("[DEB] Detect only mode is enabled, performing no assesment of " +
                  "CMPs or Vendors.")
        print(f"[DEB] Running with {args.threads} threads")

'''
Function to verify a valid command was supplied with all needed parameters, and 
check if tcstring utility is available
'''
def validate_command():
    if ( args.debug ) :
        print("[DEB] Validating command")
    # Single url, or input file must be present, but not both, file should exist
    if ( args.url == None and args.list == None ) :
        print("[ERR] -u or -l option must be used")
        sys.exit("Invalid command.")
    if ( args.url != None and args.list != None ) :
        print("[ERR] -u and -l option cannot both be used")
        sys.exit("Invalid command.")
    if ( args.list != None and not os.path.isfile(args.list) ) :
        print("[ERR] Supplied input file does not exist")
        sys.exit("Invalid command.")
    if ( args.output != None and os.path.isfile(args.output) ) :
        print(f"[ERR] Supplied output file already exists")
        sys.exit("Invalid command.")
    # Check if tcstring utility is installed
    output = os.popen(f"tcstring 2>/dev/stdout").read()
    if not ( output == "Please pass a TC string\n" ) :
        print(f"[ERR] tcstring utility seems not to be installed, please " +
              "install first")
        sys.exit("Invalid command.")
    # TODO: check if selenium is installed?

'''
Increment functions that handle keeping count of (non) detections and errors, 
and store these in global variables
'''
def increment_total_tested():
    global total_tested
    threadLock1 = threading.Lock()
    with threadLock1 : total_tested += 1
        
def increment_error():
    global errors
    threadLock2 = threading.Lock()
    with threadLock2 : errors += 1

def increment_tcf_detection():
    global count_TCF_detections 
    threadLock3 = threading.Lock()
    with threadLock3 : count_TCF_detections += 1 

def increment_tcf_non_detection():
    global count_TCF_non_detections
    threadLock4 = threading.Lock()
    with threadLock4 : count_TCF_non_detections += 1

def increment_identifiers_detected():
    global count_cookie_identifiers_detected
    threadLock5 = threading.Lock()
    with threadLock5 : count_cookie_identifiers_detected += 1

def increment_filtered_out():
    global filtered_out
    threadLock6 = threading.Lock()
    with threadLock6 : filtered_out += 1

def increment_consent_before_interaction():
    global consent_before_interaction
    threadLock7 = threading.Lock()
    with threadLock7 : consent_before_interaction += 1

def increment_injected_string_not_returned():
    global injected_string_not_returned
    threadLock8 = threading.Lock()
    with threadLock8 : injected_string_not_returned += 1

def increment_failed_injection():
    global failed_injection
    threadLock9 = threading.Lock()
    with threadLock9 : failed_injection += 1

def increment_violating_purpose():
    global violating_purpose 
    threadLock10 = threading.Lock()
    with threadLock10 : violating_purpose += 1

def increment_violating_vendor():
    global violating_vendor 
    threadLock11 = threading.Lock()
    with threadLock11 : violating_vendor += 1

def increment_undisclosed_cookie():
    global undisclosed_cookie
    threadLock12 = threading.Lock()
    with threadLock12 : undisclosed_cookie += 1

def increment_vendor_not_in_gvl():
    global vendor_not_in_gvl
    threadLock13 = threading.Lock()
    with threadLock13 : vendor_not_in_gvl += 1

'''
Function that configures a new crawler for each URL visit
'''
def configure_crawler():
    configured = False
    consecutive_errors = 0 
    max_consecutive_errors = 20

    while ( not configured ) :
        try: 
             driver: webdriver.Chrome()
             service = Service(executable_path="/usr/bin/chromedriver")
    
             chrome_options = Options()
             chrome_options.BinaryLocation = "/snap/bin/chromium"

             chrome_options.add_argument("--enable-javascript")

# options to accept third party cookies:
             chrome_options.add_experimental_option("prefs", {"profile.default_content_setting_values.cookies": 1})
             chrome_options.add_experimental_option("prefs", {"profile.block_third_party_cookies": False})

# enable BiDi to access third party cookies
             chrome_options.enable_bidi = True
             driver = webdriver.Chrome(service=service, options=chrome_options)
             driver.set_page_load_timeout(30)
             driver.command_executor.set_timeout(90)
             configured = True
             consecutive_errors = 0
        except Exception as e : 
            print(f"[ERR] Exception while configuring crawler. ({consecutive_errors}" +
                  f"/{max_consecutive_errors})")

            if ( args.debug ) : print(f"[DEB] Errormessage: {e}")
            time.sleep(10 * TIME_FACTOR)
            consecutive_errors += 1 
            if ( consecutive_errors >= max_consecutive_errors ): 
                print(f"[ERR] {max_consecutive_errors} consecutive errors while " +
                      "configuring crawler, killing all chrome processes")
                os.popen(f"killall chrome")
                consecutive_erros = 0 
                if ( args.debug ) : 
                    print(f"[DEB] Errormessage of last exception: \n {e} ")
    return driver

def stop_driver(driver) :
    try:
        driver.quit()
    except Exception as e: 
        print(f"[ERR] Exception while stopping driver: \n{e}")
        if ( args.debug ) : print(f"[DEB] Exception while stopping driver: \n{e}")

'''
Read accept strings from json file, using the configured language from the command. 
These strings will be used while trying to identify the accept-all button in a 
cookie dialog during the detection phase.
'''
def prepare_accept_strings() :
    accept_strings = []
    languages_cmd = args.language.split(',')
    # For each language in command, add accept strings from JSON file
    for param in languages_cmd : 
        for language in DIALOG_ACCEPT_STRINGS :
            if ( param == DIALOG_ACCEPT_STRINGS[f"{language}"]['parameter'] ) :
                strings_to_add = DIALOG_ACCEPT_STRINGS[f"{language}"]['strings']
                accept_strings = accept_strings + strings_to_add
    # Remove duplicates
    accept_strings_unique = list(set(accept_strings))
    return accept_strings_unique

'''
If URLs are read from a file, this function will place them in a list to be 
proccessed by the worker threads
'''
def prepare_url_list() :
    url_list = []
    if ( args.list == None ) :
        url_list = [ args.url ] 
        if ( args.debug ) : print(f"[DEB] Placed url from command in list")
    else :
        with open (args.list) as file :
            for line in file :
                url_list.append(line.strip())
        if ( args.debug ) : print(f"[DEB] Placed urls from file in list")
        if ( len(url_list) == 0 ) :
            sys.exit(f"[ERR] Supplied input file did not contain any URLs")
    return url_list

'''
Strip any paths, and http/https protocol from candidate URLs 
'''
def remove_path(url):
    result = "" 
    if ( "http" in url ) :
        parsed = urlparse(url)
        result = parsed.hostname
    else :
        result = url.split("/", 1)[0]
    return result

'''
Query a number of specialized DNS servers in order to verify the domain being 
processed is not known to be unsafe or contain unwanted or inapropriate content.
'''
def filter_unsafe_domain(domain) :
    safe = True
    resolver = dns.resolver.Resolver()
    dns_servers = DNS_RESOLVERS['resolvers']
    for server in dns_servers :
        try:
            ip = server['IP']
            name = server['name']
            resolver.nameservers = [ ip ]
            resolver.timeout = 1
            resolver.lifetime = 1
            result = resolver.resolve(domain)
            if ( result[0].to_text() == '0.0.0.0' ) :
                safe = False
                increment_filtered_out()
                if ( args.debug ) : 
                    print(f"[DEB] Domain {domain} was filtered out by domain name " +
                          f"server {name}")
                break
        except Exception :
            if ( args.debug ) : print(f"[DEB] Error resolving domain name")
    return safe

'''
Function to navigate to a webpage using the selenium webdriver
'''
def navigate_to_url(driver, domain) :
    url = str("https://" + domain)
    driver.get(url)
    time.sleep(3 * TIME_FACTOR)

'''
Function to detect the use of the TCF on a website, based on the pressence of 
the __tcfapi fucntion.
'''
def detect_tcf(driver, domain) :
    TCF_detected = False
    RETRIES = 0
    succes = False
    while ( RETRIES < MAX_RETRIES and not succes ) :
        try:
            navigate_to_url(driver, domain)

            # Detect __tcfapi function using Selenium scripting capabilities
            if ( driver.execute_script("return typeof window.__tcfapi") == "function" ) :
                TCF_detected = True
                if ( args.verbose or args.debug ) : 
                    print(f"[VER] TCF detected on URL {domain}")
                if ( args.debug ) :
                    print("[DEB] Used detection method: __tcfapi function")
            else:
                if ( args.debug ) : print(f"[DEB] did not detect TCF")
            succes = True
        except Exception as e :
            if ( RETRIES == MAX_RETRIES ) :
                print(f"[ERR] Errors occured {RETRIES} times while detecting TCF " +
                      f"({domain})")
                if ( args.debug ) : 
                    print(f"[DEB] Errormessage: \n {e}")
            RETRIES += 1
    if ( not succes ) :
        increment_error()
    if ( TCF_detected ) :
        increment_tcf_detection()
    if ( succes and not TCF_detected ) :
        increment_tcf_non_detection()
    return TCF_detected

'''
Function to check if a string contains a TC string. Uses the "tcstring"
command line utility from the IAB at 
https://github.com/InteractiveAdvertisingBureau/iabtcf-es/tree/master/modules/cli#iabtcfcli
'''
def isTCString(string, URL_encoding = False ) :
    TCstring_detected = False
    additional_data = False
    prefix = ""
    suffix = ""

    # TCstrings start with characters for version, year and month, we can use
    # these like a magic header to perform a quick first check
    if ( string.startswith(TCSTRING_MAGIC_HEADER) ) :
        # Strip out dangerous characters to prevent code injection vulnerabilities
        sanitized_string = string.translate({ord(c): None for c in ';"|&'})
        try: 
            # Verify the TC string using tcstring utility, if the string
            # "encoded" is present, the utility successfully decoded the TC string. 
            decoded = decode_TC_string(f"{sanitized_string}")
            if ( "encoded" in decoded ) :
                if ( args.debug ) : print("[DEB] TC string detected")
                TCstring_detected = True
        except Exception :
            pass
    
    if ( string != None and not TCstring_detected and TCSTRING_MAGIC_HEADER in string ) :

        # Likely a URL encoded value, decode and recursively call isTCString again
        if ( "%" in string ) :
            url_decoded = unquote(string)
            TCstring_detect = isTCString(url_decoded, True)
            if ( TCstring_detect[0] ) :
                TCstring_detected = True
                additional_data = True
                URL_encoding = True
                prefix = TCstring_detect[3]
                suffix = TCstring_detect[4]

        elif ( "\"" in string ) :
        # Multiple values, possibly json, double quotes expected around TCstring
        # value
            substrings = string.split("\"")
            TC_string = ""
            for sub in substrings :
                if ( not TCstring_detected ) :
                    TCstring_detect = isTCString(sub, URL_encoding)
                    if ( TCstring_detect[0] ) :
                        TCstring_detected = True
                        additional_data = True
                        TC_string = sub
            # TCstring is found, with additional data around it, save the prefix 
            # and suffix to use for injection later
            if ( TCstring_detected ) :
                prefix = string.split(TC_string)[0]
                suffix = string.split(TC_string)[1]
                if ( URL_encoding ) :
                    prefix = quote_plus(prefix)
                    suffix = quote_plus(suffix)

    return (TCstring_detected, additional_data, URL_encoding, prefix, suffix)

'''
function that uses selenium function to retrieve all cookies and check these
for containing a TC String. 
Returns a tuple of a string and boolean, the string contains the cookie 
identifier of the cookie containing a TC string, and is empty if none is 
found. The boolean is true when other data is in the same cookie value
'''
# We could compare the TC string found in a cookie with the one retrieved by 
# the __tcfapi call, to verify we really have the correct storage mechanism
def detect_TCstring_cookie(driver, url) :
    additional_data = False
    URL_encoding = False
    prefix = ""
    suffix = ""
    TCstring_cookie_detected = False
    TCstring_cookie = ""
    TCstring_during_detection = ""
    try:
        # Use Selenium driver to retrieve cookies in JSON format
        cookies = driver.get_cookies()
        if ( args.debug ) : print("[DEB] Detected cookies: ")
        for cookie in cookies :
            parsed_cookie = json.loads(json.dumps(cookie))
            if ( args.debug ) : 
                print(f"      {parsed_cookie['name']}")
            if ( parsed_cookie['name'] in COMMON_TC_COOKIES ) :
                test_string_for_TC_string = isTCString(parsed_cookie['value'])
                if ( test_string_for_TC_string[0] ) :

                    TCstring_cookie_detected = True
                    TCstring_cookie = parsed_cookie['name']
                    additional_data = test_string_for_TC_string[1]
                    URL_encoding = test_string_for_TC_string[2]
                    prefix = test_string_for_TC_string[3]
                    suffix = test_string_for_TC_string[4]
                    increment_identifiers_detected()
                    if ( args.debug or args.verbose ) : 
                        print(f"[VER] Cookie with common identifier " +
                              f"'{TCstring_cookie}' found ({url})")
                    if ( args.debug ) : 
                        print(f"[DEB] Value cookie: {parsed_cookie['value'][:1000]}")
                    break
                else :
                    if ( args.debug ) : 
                        print(f"[DEB] {TCstring_cookie} however does not contain " +
                              f"valid TC String ({url})")
    # TCstring not found in cookie with common name, continue checking all cookies        
        for cookie in cookies :
            if ( not TCstring_cookie_detected ) :
                parsed_cookie = json.loads(json.dumps(cookie))
                test_string_for_TC_string = isTCString(parsed_cookie["value"])
                if ( parsed_cookie['name'] not in FALSE_INJECTION_POINTS and test_string_for_TC_string[0] ) :
                    TCstring_cookie_detected = True
                    additional_data = test_string_for_TC_string[1]
                    URL_encoding = test_string_for_TC_string[2]
                    prefix = test_string_for_TC_string[3]
                    suffix = test_string_for_TC_string[4]
                    TCstring_cookie = parsed_cookie["name"]
                    increment_identifiers_detected()
                    if ( args.debug or args.verbose ) : 
                        print(f"[VER] Cookie with identifier '{TCstring_cookie}' " +
                              f"contains TCString ({url})")
                    if ( args.debug ) : 
                        print(f"[DEB] Value cookie: {parsed_cookie['value'][:1000]}")
        TCstring_during_detection = getTCstring_via_API(driver)
        if ( args.debug ) :
            print(f"[DEB] TC string retrieved from __tcfapi: " +
                  f"{TCstring_during_detection} ({url})")
    # if cookie with TC string still not found, maybe check also cookies marked as false injection points..
    except Exception as e : 
        print(f"[ERR] Exception while reading cookies ({url})")

        if ( args.debug ) : print(f"[DEB] Errormessage: \n {e}")
    return (TCstring_cookie, additional_data, URL_encoding, prefix, suffix, TCstring_during_detection)

'''
Function that uses selenium function to retrieve Local Storage items and check
these for containing a TC String. 
Returns a tuple of a string and boolean, the string contains the key 
of the Local Storage item containing a TC string, and is empty if none is 
found. The boolean is true when other data is in the same value
'''
# We could compare the TC string found in a Local Storage item with the one 
# retrieved by the __tcfapi call, to verify we really have the correct storage 
# mechanism
def detect_TCstring_in_Local_Storage(driver, url) :
    TCstring_LS_detected = False
    TCstring_LS = ""
    prefix = ""
    suffix = ""
    additional_data = False
    URL_encoding = False
    TCstring_during_detection = ""

    if ( args.debug ) : 
        print("[DEB] No cookie containing TCstring found, checking Local Storage " +
              f"({url}) \n[DEB] Local Storage items: ")
    try: 
        # Retrieve all keys of Local Storage items
        for key in driver.execute_script("return Object.assign({}, window." + 
                                         "localStorage);") :
            # For all keys, if they are not known as a false injection point,
            # return the value, until a TC string is found
            if ( key not in FALSE_INJECTION_POINTS and not TCstring_LS_detected ) :
                try: 
                    if (args.debug) : print(f"      {key}")
                    value = driver.execute_script(f"return window.localStorage" +
                                              f".getItem('{key}');")
                    test_string_for_TC_string = isTCString(value)
                    # Valid TC string is found, capture additional data, encoding, 
                    # prefix and suffix if applicable
                    if ( test_string_for_TC_string[0] ) :

                        TCstring_LS_detected = True
                        TCstring_LS = key
                        additional_data = test_string_for_TC_string[1]
                        URL_encoding = test_string_for_TC_string[2]
                        prefix = test_string_for_TC_string[3]
                        suffix = test_string_for_TC_string[4]
                        increment_identifiers_detected()
                        if ( args.debug or args.verbose ) : 
                            print(f"[VER] Local Storage item with key '{key}' contains " +
                                  f"TCString ({url})")
                        if ( args.debug ) : print(f"[DEB] Value item: {value[:1000]}")
                except Exception :
                    pass

        if ( not TCstring_LS_detected and args.debug ) : 
            print(f"[DEB] No TCstring found in Local Storage ({url})")
        TCstring_during_detection = getTCstring_via_API(driver)

    except Exception as e :
        print(f"[ERR] Exception occured while reading Local Storage ({url})")
        if ( args.debug ) : print(f"[DEB] Errormessage: \n{e}")
    return (TCstring_LS, additional_data, URL_encoding, prefix, suffix, TCstring_during_detection)

'''
Function to attempt to find the accept button for CMPs that use a shadow host 
in their implementation. Since Selenium has limited capabilities in searching 
within a shadow hosts root, either an identifier or class name needs to be known 
in advance. 
'''
def identify_accept_button_shadow_host(driver, host_method, host_value, button_method, button_value) :
    try:
        if ( host_method == "id" ) :
            shadow_host = driver.find_element(By.ID, host_value)
        if ( host_method == "tag_name" ) :
            shadow_host = driver.find_element(By.TAG_NAME, host_value)
        if ( host_method == "class_name" ) :
            shadow_host = driver.find_element(By.CLASS_NAME, host_value)
        shadow_root = shadow_host.shadow_root
        if ( button_method == "id" ) :
            accept_button = shadow_root.find_element(By.ID, button_value)
        if ( button_method == "class_name" ) :
            accept_button = shadow_root.find_element(By.CLASS_NAME, button_value)
#        if ( button_method == "css" ) :
#            print("trying css")
#            accept_button = shadow_root.find_element(By.CSS_SELECTOR, button_value)
        return accept_button
    except Exception as e :
        if ( args.debug ) :
            print(f"[DEB] Exception while identifying acceptbutton in shadow " +
                  f"root ({url}): \n{e}")

'''
Function to attempt to find the acceptbutton for CMPs for which button identifiers 
or class names are known beforehand.
'''
def identify_accept_button(driver, button_method, button_value) :
    try:
        if ( button_method == "id" ) :
            accept_button = driver.find_element(By.ID, button_value)
        if ( button_method == "class_name" ) :
            accept_button = driver.find_element(By.CLASS_NAME, button_value)
        return accept_button
    except Exception as e :
        if ( args.debug ) :
            print(f"[DEB] Exception while identifying acceptbutton ({url}): \n{e}")

'''
Function to interact with a cookiedialog if available. Will search for common 
text contents of "accept all" buttons. Also tries to identify certain CMPs 
that use a shadow root to serve the cookie dialog, and cookie dialogs in 
iframes
'''
def interact_dialog_accept_all(driver, url) :
    interacted = False

    # Try to identify the CMP based on html source tag, nessecary to interact
    # with CMPs that use a shadowroot
    for CMP in CMP_SPECIFICATION :
        SPECIFICATION = CMP_SPECIFICATION[CMP]
        try :
            identifier = driver.find_element(By.XPATH,"//*[contains(@src,'" + 
                                             SPECIFICATION['source_identifier'] + "')]") 
            if ( args.debug ) : 
                print(f"[DEB] cmp identified by {SPECIFICATION['source_identifier']}")
            if ( SPECIFICATION['uses-shadow-host'] ) : 
                 # CMP is known to use shadowroot
                 accept_button = identify_accept_button_shadow_host(driver, SPECIFICATION['shadow-root']['type'], SPECIFICATION['shadow-root']['value'], SPECIFICATION['accept-button']['type'], SPECIFICATION['accept-button']['value'])
            else :
                # CMP is not known to use shadowroot
                accept_button = identify_accept_button(driver, SPECIFICATION['accept-button']['type'], SPECIFICATION['accept-button']['value'])

            accept_button.click()
            interacted = True
            break
        except ElementClickInterceptedException :
            # other element seems to be blocking the accept button, this sometimes 
            # seems to be done on purpose as a anti-automation mechanism
            driver.execute_script("arguments[0].click();", accept_button)
            interacted = True
        except Exception as e:
            pass 
 
    # Try to locate a (button with a) span, button or p element with a 
    # common accept string 
    if ( not interacted ) :
        # Translate text found in webpage elements to lowercase, for case-
        # insensitive search
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        element_types = [ "span", "button", "p" ] #"*" ]

        # Loop over strings that are commonly found on accept-all buttons, 
        # trying to find an element we can click
        for string in ACCEPT_STRINGS :
            for element in element_types :
                try :
                    xpath = f"//{element}[contains(translate(text(), '{uppercase}'" + \
                            f", '{lowercase}'), '{string}')]"
                    accept_button = driver.find_element(By.XPATH, xpath)
                    if ( args.debug ) : 
                        print(f"[DEB] Found button with string: {string}")
                    accept_button.click()
                    interacted = True
                    break
                except Exception :
                    pass

    # Try to locate an iframe in which the accept button could be located
    if ( not interacted ) :
        for iframe_identifier in IFRAME_IDENTIFIERS :
            if ( interacted ) :
                break
            try :
                iframe = driver.find_element(By.XPATH,"//iframe[contains(@src,'" + 
                                             iframe_identifier + "')]")
                if ( args.debug ) : print("[DEB] Searching for accept button in iframe 1")
                driver.switch_to.frame(iframe)
                elements = driver.find_elements(By.XPATH, '//button')
                for element in elements:
                    for string in ACCEPT_STRINGS :
                        try: 
   #                     for string in ACCEPT_STRINGS :
                            text_lower = element.text.lower()
                            if ( string in text_lower ) :
                                if ( args.debug ) : 
                                    print(f"[DEB] Found button with string: {string}")
                                element.click()
                                interacted = True
                                driver.switch_to.default_content()
                                break
                        except Exception: 
                            pass
                driver.switch_to.default_content()
            except Exception :
                pass
            try : 
                iframe = driver.find_element(By.XPATH,"//iframe[contains(@title,'" + 
                                             iframe_identifier + "')]")
                driver.switch_to.frame(iframe)
                if ( args.debug ) : print("[DEB] Searching for accept button in iframe")
                elements = driver.find_elements(By.XPATH, '//button')
            
                for element in elements:
                    for string in ACCEPT_STRINGS :
                        try: 
#                        for string in ACCEPT_STRINGS :
                            text_lower = element.text.lower()
                            if ( string in text_lower ) :
                                if ( args.debug ) : 
                                    print(f"[DEB] Found button with string: {string}")
                                element.click()
                                interacted = True
                                driver.switch_to.default_content()
                                break
                        except Exception: 
                            pass
                driver.switch_to.default_content()
            except Exception :
                pass
 
    # No button was found to interact with
    if ( not interacted ) :
        if ( args.debug or args.verbose ) : 
            print(f"[ERR] Failed to interact with cookie dialog. ({url})")
        if ( args.screenshot ) :
            take_screenshot(driver, url)

    # Give website time to execute EventListener and store TC string
    time.sleep(2 * TIME_FACTOR)
    status = getTCFAPI_status(driver)
    if ( f"{status}" == "cmpuishown" ) :
        # Failed to interact with cookie dialog. if a default TC string can be 
        # found in a cookie or local storage item we can still try to proceed. 
        # We return failed interaction to prevent a false positive detection 
        # for server-side storage mechanism, since the default TC string will 
        # be found during detection and injected when assessing the CMP. 
        if ( args.debug or args.verbose ) :
            print(f"[ERR] Failed to interact with cookie dialog, status is " +
                  f"\"cmpuishown\". ({url})")
        interacted = False
    else :
        if ( args.debug ) :
            print(f"[DEB] __tcfapi has returned status: {status}.")
    return interacted

'''
Function to identify the CMP that is used on a website, by calling the __tcfapi.
'''
def identify_CMP(driver) :
    CMP_ID = 0
    try :
        script = "window.__tcfapi('ping',2,function(data,success)" + \
                 "{window.result=data;}); return window.result"
        output_json = driver.execute_script(script)
        parsed_output = json.loads(json.dumps(output_json))
        CMP_ID = parsed_output['cmpId']
    except Exception as e :
        if ( args.debug ) :
            if ( "window.__tcfapi is not a function" in f"{e}" ): 
                print(f"[DEB] __tcfapi function not found, possible bot-detection?!")
            else :
                print(f"[DEB] Exception while retrieving CMP ID via __tcfapi, " +
                      f"errormessage: {e}")
    return CMP_ID

'''
Function to retrieve the TC string, by calling the __tcfapi, using selenium 
scripting capabilities
'''
def getTCstring_via_API(driver) :
    retrieved_TC_string = ""
    try : 
        script = "window.__tcfapi('addEventListener', 2, function(tcData, success)" + \
                 "{window.result=tcData;}); return window.result"
        output_json = driver.execute_script(script)
        if ( output_json is not None ) :
            parsed_output = json.loads(json.dumps(output_json))
            retrieved_TC_string = parsed_output['tcString']
    except Exception as e:
        if ( args.debug ) :
            if ( "window.__tcfapi is not a function" in f"{e}" ): 
                print(f"[DEB] __tcfapi function not found, possible bot-detection?!")
            else :
                print(f"[DEB] Exception while retrieving TC string via __tcfapi, " +
                      f"errormessage: {e}")
    return retrieved_TC_string

'''
Function to retrieve the CMP status value from the __tcfapi, useful to analyze 
a failed injection
'''
def getTCFAPI_status(driver) :
    retrieved_status = ""
    try :
        script = "window.__tcfapi('addEventListener', 2, function(tcData, success)" + \
                 "{window.result=tcData;}); return window.result"
        output_json = driver.execute_script(script)
        if ( output_json is not None ) :
            parsed_output = json.loads(json.dumps(output_json))
            retrieved_status = parsed_output['eventStatus']
    except Exception as e: 
        if ( args.debug ) : print(f"Exception while getting status from __tcfapi," +
                                  f" \nerrormessage: {e}")
        pass
    return retrieved_status
 

def encode_TCstring() :
    pass

'''
Function to get a TCstring with a certain CMP identifier and configuration, will 
first check if this string has previously been encoded, and will reuse it. If not
previously used it will encode a new one and store it in the TCSTRINGS list
'''
def get_TCstring(cmpID, purposes, vendors) :
    global TCSTRINGS
    # Check if string with requested cmpID and configuration has previously been 
    # encoded and is present in TCSTRINGS list
    tcstring = [string for string in TCSTRINGS if string[0] == cmpID and string[1] == purposes and string[2] == vendors ]
    if ( not tcstring ) : 
        # TCstring is empty list
        # TCstring with this cmpID and configuration has not been encoded yet, 
        # we will do this now, and add it to the list for re-use later
        TCstring = encode_TC_string_online(cmpID, purposes, vendors)
        new_entry_tcstrings = (cmpID, purposes, vendors, TCstring)
        TCSTRINGS.append(new_entry_tcstrings) 
    else :
        # TCstring with cmpID and configuration is present in TCSTRINGS list, we 
        # can reuse it
        TCstring = tcstring[0][3]
        if ( args.debug ) : 
            print(f"[DEB] TCstring with cmpID \"{cmpID}\", purposes '{purposes}' " +
                  f"and vendors '{vendors}' reused")
    return TCstring
    
'''
Use selenium to interact with online encode tool from TCF at iabtcf.com/"/encode
'''
def encode_TC_string_online(cmpID, purposes, vendors) :
    succes = False
    TC_string = ""
    url = URL_ONLINE_ENCODER
    retries = 0
    try : 
        driver = configure_crawler()
        navigate_to_url(driver, url)
        if ( args.debug ) : print(f"[DEB] encoding TC string with online tool")

        while ( not succes and retries < MAX_RETRIES ) :
            # Set cmpID to match with the CMP implementation
            CMP_ID_input = driver.find_element(By.ID, '__BVID__36')
            ActionChains(driver).scroll_to_element(CMP_ID_input).perform()
            CMP_ID_input.clear()
            CMP_ID_input.send_keys(cmpID)

            
            # This field will contain the encoded TCstring
            TC_string_field = driver.find_element(By.CLASS_NAME, "tcstring-input")

            # We enable Service Specific for all TC strings or it will not always 
            # be accepted by the CMP implementation
            isServiceSpecific_button =  driver.find_element(By.XPATH, "//label" +
                                                            "[@for='isServiceSpecific']")
            isServiceSpecific_button.click()

#            Vendor_list_version = driver.find_element(By.ID, 'vendorListVersion')
#            ActionChains(driver).scroll_to_element(Vendor_list_version).perform()
#            Vendor_list_version.send_keys("105") #TODO make parameter!!
#            Vendor_list_version.send_keys(Keys.ENTER)

            if ( purposes == "all" ) :
                # Select all purposes by clicking and sending ctrl + a
                purpose_selector = driver.find_element(By.XPATH, f"//select"+
                                                       "[@id='purposeConsents']")
                ActionChains(driver).scroll_to_element(purpose_selector).perform()
                purpose_selector.click()
                purpose_selector.send_keys(Keys.CONTROL + "a")
            elif ( purposes != "none" ) : 
                # Select a set of purposes one by one
                for purpose in purposes :
                    purpose_selector = driver.find_element(By.XPATH, f"//select" +
                                                           "[@id='purposeConsents']" +
                                                           f"//option[@value={purpose}]")
                    purpose_selector.click()

            if ( vendors == "all" ) :
                # Select vendors option and send ctrl + a to select all
                vendor_selector = driver.find_element(By.XPATH, f"//select" +
                                                      "[@id='vendorConsents']")
                ActionChains(driver).scroll_to_element(vendor_selector).perform()
                vendor_selector.click()
                vendor_selector.send_keys(Keys.CONTROL + "a")
            elif (vendors != "none" ) :
                # Select a set of vendors one by one
                for vendor in vendors :
                    vendor_selector = driver.find_element(By.XPATH, f"//select" +
                                                          "[@id='vendorConsents']" +
                                                          f"//option[@value={vendor}]")
                    vendor_selector.click()
            succes = True
        time.sleep(2 * TIME_FACTOR)
        # Get the encoded TC string value
        TC_string = TC_string_field.get_attribute("value")
    except Exception as e:
#        print(f"[DEV] exception while encoding TC string with online tool:\n{e}")
        retries += 1
        pass
    return TC_string

'''
Function to decode a TC string using the commandline tcstring utility from the 
IAB repository
'''
def decode_TC_string(string) :
    #run IABs tcstring utility to verify the TC string
    decoded = os.popen(f"tcstring {string} 2>/dev/null").read() 
    return decoded
    
'''
Function which assesses compliance of a CMP on a website. First is checked if a 
TC string is available via the tcfapi function before user interaction with the 
cookie dialog. If so this TC string is checked to verify it does not give consent 
for any vendors. Next a TC string is encoded to not allow any vendors, this 
TCstring is then injected into the browser, using the previously detected mechanism,
identifier and prefix and suffix. The tcfapi function is again used to retrieve 
a TCstring, which is compared to the injected string. 
'''
def assess_CMP(driver, cmpID, mechanism, identifier, domain, prefix, suffix, TCstring_during_detection) :
    assessment_result = ""
    attempts = 0 
    finished = False
    injection_success = True
    default_set_TC_string = ""
    if ( args.debug ) : print(f"\n[DEB] Starting CMP assessment")
    
    # Start step 1: Load the page and see if a TCstring is present before interaction
    while ( attempts < MAX_RETRIES and not finished ) :
        try: 
            # Restart driver, since on some websites removing cookies and clearing
            # Local Storage does not reset given consent... 
            stop_driver(driver)
            driver = configure_crawler()
            navigate_to_url(driver, domain)

            # Get the TC string by calling __tcfapi
            retrieved_TC_string = getTCstring_via_API(driver)

            # Store the string we just retrieved for comparison after the first
            # injection, to see if injection will be successful
            default_set_TC_string = retrieved_TC_string

            if ( retrieved_TC_string != "" ) :
                if ( args.verbose or args.debug ) :
                    print(f"[VER] TCstring is returned by __tcfapi before " +
                          "interaction with cookie dialog. We should check the " +
                          f"consent encoded in this default TCstring. ({domain})")
                if ( args.debug ) : 
                    print(f"[DEB] Returned TCstring is: {retrieved_TC_string}")
                # Check that the retrieved TC string is not the same as the one 
                # found during the detection phase. If it is the same, the storage 
                # persisted after starting a new browser instance. This could 
                # indicate a server side storage mechanism?
                possible_persistance = ""
                if ( retrieved_TC_string == TCstring_during_detection ) :
                    if ( args.debug ) :
                        print(f"[ERR] TC string retrieved before injection is " +
                              "equal to the TC string found during the detection " +
                              "phase. The TC string persisted after starting a new " +
                              "browser instance, this could indicate a server side " +
                              "storage mechanism. Or this could mean that interaction " +
                              f"with the dialog during detection failed. ({domain})")
                        possible_persistance = "(or persisted) "
                        status = getTCFAPI_status(driver)
                        print(f"[DEB] __tcfapi has retuned status: {status}.")
                    assessment_result = assessment_result + " same TC string " + \
                          "returned before injection as during detection after " + \
                          "interaction (server-side storage; failed interaction " + \
                          "or CMP error);"
                    # If the string before interaction is equal to the one found 
                    # during detection we can not use this for injection, since we 
                    # won't know if it is succesful. We set it to an empty string 
                    # now, and encode a custom one in the next step
                    TCstring_during_detection = ""

                # Check that the retrieved TC string does not allow consent for 
                # any vendors
                assert_result = assert_TCstring_allows_no_vendors(retrieved_TC_string)
                no_vendors_allowed = assert_result[0]
                allowed_vendors = assert_result[1]

                # Check that the retrieved TC string does not allow consent for 
                # any purposes
                assert_result = assert_TCstring_allows_no_purposes(retrieved_TC_string)
                no_purposes_allowed = assert_result[0]
                allowed_purposes = assert_result[1]

                if ( no_vendors_allowed and no_purposes_allowed ) : 
                    if ( args.debug or args.verbose ) :
                        print(f"[VER] Default set {possible_persistance}TCstring " +
                              "does not give consent for any vendors or purposes " +
                              f"({domain})")
                elif ( no_vendors_allowed and not no_puroses_allowed ) :
                    if ( args.debug or args.verbose ) :
                        print(f"[VER] Default set {possible_persistance}TCstring " +
                              "does not give consent for any vendors, but does " + 
                              f"for the following purposes: {allowed_purposes} " +
                              f"({domain}).")
                elif ( not no_vendors_allowed and no_purposes_allowed ) :
                    if ( args.debug or args.verbose ) :
                        print(f"[VER] Default set {possible_persistance}TCstring " + 
                              "does not give consent for any purposes, but does " +
                              f"for the following vendors: {allowed_vendors} " +
                              f"({domain}).")
                else :
                    print(f"[!!!] TCstring set without interaction " +
                          f"{possible_persistance}gives consent to the following " +
                          f"vendors: {allowed_vendors}\nand the following purposes: " +
                          f"{allowed_purposes} ({domain}).\nThis should be " +
                          f"investigated. ({domain})")
                    increment_consent_before_interaction()
                    assessment_result = assessment_result + "CMP allows vendors " + \
                                                  "and purposes before interaction;"

                finished = True
            else :
                # getTCstring_via_API() returned an empty string, likely an 
                # exception while executing script in browser
                attempts += 1

        except Exception as e:
            # __tcfapi did return a value, but one indicating the cookie dialog 
            # is not yet interacted with. TCstring therefore not available via 
            # API call
            if ( 'parsed_output' in locals() and parsed_output['eventStatus'] == "cmpuishown" ) :
                if ( args.debug ) :
                    print(f"[DEB] tcfapi returned eventStatus of \"tcloaded\", " + 
                          "TCstring not yet available via API call")
                finished = True
            else :
                if ( args.debug ) : 
                    print(f"[DEB] Exception during CMP assessment, errormessage:\n{e}")
            attempts += 1

    # No need to proceed if a server-side storage mechanism is suspected
    if ( injection_success ) :
    # Start step 2: inject a TC string and check if it is returned by __tcfapi

        # Encode TC string to inject
#        TCstring = get_TCstring(cmpID, "none", "none")

        # Instead of encoding a reject all string, use the string retrieved 
        # during detection, since this must be an acceptable string for the cmp
        TCstring = TCstring_during_detection

        if ( TCstring == "" ) :
            # Possible error during detection phase, encode a TC string to inject
            # instead of using an empty string
            TCstring = get_TCstring(cmpID, "all", "all")

        # Wrap in prefix and suffix
        TCstring_wrapped = f"{prefix}{TCstring}{suffix}"

        # Inject TC string according to storage mechanism and identifier
        retrieved_TC_string = ""

        attempts = 0 
        finished = False
        # Assess if injected string is returned by tcfapi
        while ( attempts < MAX_RETRIES and not finished ) :
            try:
                stop_driver(driver)
                driver = configure_crawler()
                navigate_to_url(driver, domain)

                if ( args.debug ) :
                    print("[DEB] Injecting TC string")

                if ( mechanism == "cookie" ) :
                    inject_TC_string_cookie(driver, TCstring_wrapped, identifier, domain)

                elif (mechanism == "LS" ) :
                    inject_TC_string_LS(driver, TCstring_wrapped, identifier, domain)

                # Reload page to simulate returning visit
                driver.refresh()
                time.sleep(2 * TIME_FACTOR)

                # Retrieve the TC string from __tcfapi, and compare to the 
                # injected string
                retrieve_and_match = check_if_injected_matches_returned(driver, TCstring)
                retrieved_matches_injected = retrieve_and_match[0]
                retrieved_TC_string = retrieve_and_match[1]
            
                if ( retrieved_TC_string == "" ) :
                    if ( args.debug ) : 
                        status = getTCFAPI_status(driver)
                        print(f"[DEB] __tcfapi returned an empty string after " +
                              "injection, injection failed. \n      __tcfapi " +
                              f"returned status: {status}.")
                    increment_failed_injection()
                    injection_success = False
                elif ( retrieved_TC_string == default_set_TC_string ) :
                    status = getTCFAPI_status(driver)
                    if ( status == "cmpuishown" ) :
                        # Cookie dialog is shown after injection, injection has 
                        # failed
                        if ( args.debug ) : 
                            print(f"[DEB] __tcfapi returned the default TC string " +
                                  "after injection, injection failed.\n      " +
                                  f"__tcfapi returned status: {status}.")
                        increment_failed_injection()
                        injection_success = False
                    else :
                        if ( args.debug ) : 
                            print(f"[DEB] __tcfapi returned the default TC string " +
                                  "after injection, but __tcfapi returned status: " +
                                  f"{status}. Attempting to proceed.")
 
                elif ( retrieved_matches_injected ) :
                    if ( args.debug ) :
                        print("[DEB] Injected TCstring matches TCstring retrieved " +
                              "with __tcfapi call")
 
                else :
                    # Injected string not equal to returned string: potential 
                    # non-compliance
                    # Check that the retrieved TC string does not allow consent
                    # for any vendors
                    assert_result = assert_TCstring_allows_no_vendors(retrieved_TC_string)
                    no_vendors_allowed = assert_result[0]
                    allowed_vendors = assert_result[1]

                    # Check that the retrieved TC string does not allow consent 
                    # for any purposes
                    assert_result = assert_TCstring_allows_no_purposes(retrieved_TC_string)
                    no_purposes_allowed = assert_result[0]
                    allowed_purposes = assert_result[1]

                    if ( no_vendors_allowed and no_purposes_allowed ) :
                        if ( args.debug ) :
                            print(f"[DEB] Injected TCstring not returned by " +
                                  "__tcfapi, returned string allows no vendors " +
                                  "or purposes")
                        injection_success = False
                        increment_failed_injection()
                    elif ( no_vendors_allowed and not no_purposes_allowed ) :
                        if ( args.debug ) :
                            print(f"[DEB] Injected TCstring not returned by " +
                                  "__tcfapi, returned string allows no vendors, " +
                                  f"but does allow purposes: {allowed_purposes}")
                        injection_success = False
                        increment_failed_injection()
                    elif ( not no_vendors_allowed and no_purposes_allowed ) :
                        if ( args.debug ) :
                            print(f"[DEB] Injected TCstring not returned by " +
                                  "__tcfapi, returned string allows no purposes, " +
                                  f"but does allow vendors: {allowed_vendors}")
                        injection_success = False
                        increment_failed_injection()
                    elif ( not no_vendors_allowed and not no_purposes_allowed ) :
                        print(f"[!!!] Injected TCstring not returned by __tcfapi, " +
                              f"returned string does allow purposes: {allowed_purposes} " +
                              f"and vendors: {allowed_vendors}, this should be " +
                              f"investigated! ({domain})")
                        increment_injected_string_not_returned()
                        assessment_result = assessment_result + " Different TCstring " + \
                        "with consent for vendors and purposes returned by tcfapi " + \
                        "after injection;"

                if ( args.debug ) :
                    print(f"[DEB] Injected TCstring: {TCstring} \n      Returned " +
                          f"TCstring: '{retrieved_TC_string}'")
                    print(f"[DEB] __tcfapi returned status: {getTCFAPI_status(driver)}.")
                finished = True
            
            except Exception as e :
                if ( args.debug ) : print(f"[DEB] Exception during CMP assesment " +
                                          f"\n[DEB] Errormessage: {e}") 
                attempts += 1
    return (assessment_result, injection_success)

'''
function to inject a cookie with certain identifier, value and domain, using 
selenium webdriver functionality.
'''
def inject_TC_string_cookie(driver, TCstring, identifier, domain) :
    try:
        cookie = {'name' : f"{identifier}", 'value' : f"{TCstring}", 'domain': f"{domain}"}
        driver.delete_all_cookies()
        driver.add_cookie(cookie)
    except Exception as e:
        if ( args.debug ) : 
            print(f"[ERR] Exception while injecting cookie ({domain})")

'''
Function to inject a TCstring into the Local Storage of the browser, using 
Selenium scripting functionality.
'''
def inject_TC_string_LS(driver, TCstring, identifier, domain) :
    try: 
        script = f"window.localStorage.setItem('{identifier}', '{TCstring}');"
        driver.execute_script(script)
    except Exception as e:
        if ( args.debug ) : 
            print(f"[ERR] Exception while injecting Local Storage ({domain})")
    pass

'''
Function to assert that a TCstring is conigured to deny consent for any vendors.
Useful for TCstrings that are being set without, or before user interaction with
a cookie dialog.
'''
def assert_TCstring_allows_no_vendors(TCstring) :
    # Should this also check if "isServiceSpecific" is set to true???
    result = True
    if ( TCstring == "" ) :
        if ( args.debug ) :
            print(f"[DEB] TC string is empty")
    else :
        # Run tcstring utility, check the vendorConsent section for any vendors
        # with value true
        command = f"tcstring {TCstring} | awk '/vendorConsents/,/vendorLegitimate" + \
                   "Interests/' | grep 'true' | cut -f 1 -d ':' | tr '\n' ' '"
        allowed_vendors = os.popen(command).read()
        if ( not len(allowed_vendors) == 0 ) :
            result = False
    return (result, allowed_vendors)

'''
Function to assert that a TCstring is configured to deny consent for any 
purposes. Useful for TCstrings that are being set without, or before user 
interaction with a cookie dialog.
'''
def assert_TCstring_allows_no_purposes(TCstring) :
    # Should this also check if "isServiceSpecific" is set to true???
    result = True
    if ( TCstring == "" ) :
        if ( args.debug ) :
            print(f"[DEB] TC string is empty")
    else :
        # Run tcstring utility, check the purposeConsent section for any purposes
        # with value true
        command = f"tcstring {TCstring} | awk '/purposeConsents/,/purposeLegitimate" + \
                   "Interests/' | grep 'true' | cut -f 1 -d ':' | tr '\n' ' '"
        allowed_purposes = os.popen(command).read()
        if ( not len(allowed_purposes) == 0 ) :
            result = False
    return (result, allowed_purposes)

'''
Function to check if an injected TC string, which is supplied, is equal to the 
TC string we will retrieve using the __tcfapi
'''
def check_if_injected_matches_returned(driver, Injected_TC_string) :
    match = False

    # Retrieve TCstring with __tcfapi to check if it matches injected string
    retrieved_TC_string = getTCstring_via_API(driver)

    if ( retrieved_TC_string == Injected_TC_string ) :
        match = True
    return (match, retrieved_TC_string)
 
'''
Function to attempt to get disclosed purposes for a certain cookie from the GVL,
by searching the GVL for the domain of the cookie, and requesting the disclosure 
JSON if found. 
'''
def get_purposes_from_GVL(domain, identifier, url_under_test) :
   purposes = []
   vendorID = 0

   # Strip off leading period if present
   if ( domain[0] == "." ) :
       domain = domain[1:]
   vendors_in_gvl = GLOBAL_VENDOR_LIST['vendors'] 
   vendor_found_in_gvl = False
   cookie_disclosure_found = False
   for vendor in vendors_in_gvl :
       if ( domain in vendors_in_gvl[vendor]['deviceStorageDisclosureUrl'] ) :
           # Vendor for this cookie found, get its disclosure 
           vendor_found_in_gvl = True
           disclosure = retrieve_device_storage_disclosure(vendor)
           vendorID = vendor

           for disclosed_cookie in disclosure :
               if ( "," in disclosed_cookie['identifier'] ) :
                   # If the cookie disclosure has multiple identifiers in single
                   # disclosure, loop over them and compare to the found cookie
                   print("[DEV] looping over multiple identifiers")
                   identifiers_in_disclosure = disclosed_cookie['identifier'].split(',')
                   for identifier_in_disclosure in identifiers_in_disclosure :
                       if ( identifier_in_disclosure == identifier ) :
                           # Cookie we were looking for found in disclosure
                           purposes = disclosed_cookie['purposes']
                           print(f"[DEV] cookie found in batch")
                           cookie_disclosure_found = True
                           break
                       # In case the cookie disclosure uses a wildcard, we should
                       # check if this matches with our found cookie
                       elif ( "*" in identifier_in_disclosure ) :
                           print(f"[DEV] batch cookie disclosure with wildcard! " +
                                 f"identifiers: {disclosed_cookie['identifier']}")
                           #TODO : match wildcard
               elif ( disclosed_cookie['identifier'] == identifier ) : 
                   # Cookie we were looking for found in disclosure
                   purposes = disclosed_cookie['purposes']
                   cookie_disclosure_found = True
                   break
               elif ( "*" in disclosed_cookie['identifier'] ) :
                   print(f"[DEV] cookie disclosure with wildcard! identifier: " +
                         f"{disclosed_cookie['identifier']}")

                   #TODO : match wildcard


           # if an exact match of the cookie identifier is not found, we shoud check if a disclosed cookie contains a wildcard, or if cookies are disclosed in batch
#           if ( not cookie_disclosure_found ) :
#               for disclosed_cookie in disclosure :
#                   if ( "," in disclosed_cookie['identifier'] ) :
#                       print(f"batch disclosure found for cookie '{disclosed_cookie['identifier']}' for domain '{disclosed_cookie['domain']}'")
#                       batch_cookies = disclosed_cookie.split(",")
#                       for batch_cookie in batch_cookies :
#                           if ( batch_cookie == identifier ) :
#                               print(f"cookie found in batch")
#                               #cookie we were looking for in batch
#                               purposes = disclosed_cookie['purposes']
#                               cookie_disclosure_found = True
#                               break
           break
   if ( not vendor_found_in_gvl ) :
       increment_vendor_not_in_gvl()
       if ( args.debug or args.verbose ) :
           print(f"[VER] No vendor found in Global Vendor List for cookie " +
                 f"'{identifier}' with domain '{domain}' ({url_under_test})")
   elif ( len(purposes) == 0 ) :
       increment_undisclosed_cookie()
       if ( args.debug or args.verbose ) :
           print(f"[VER] Vendor found in Global Vendor List, but no disclosure " +
                 f"found for cookie '{identifier}' from domain '{domain}' " +
                 f"({url_under_test})")
   else :
       if ( args.debug ) :
           print(f"[DEB] Cookie with identifier '{identifier}' is disclosed to " +
                   f"have purposes: {purposes}")
   return (purposes, vendorID)

'''
Function to retrieve the publicly declared cookies by an Adtech vendor. These 
are available as JSON files from URLs that can be found in the Global Vendor 
List (GVL). 
If a cookie disclosure is downloaded, it is kept in memory for the rest of the 
run, to avoid having to download the same JSON multiple times. 
'''
def retrieve_device_storage_disclosure(vendor) :
    global STORAGE_DISCLOSURES
    disclosed_cookies = {}
    if ( vendor not in STORAGE_DISCLOSURES ) :
        # Disclosure not yet retrieved, download it now
        finished = False
        attempts = 0
        while ( attempts < MAX_RETRIES and not finished ) :
            try:
                disclosure_url = GLOBAL_VENDOR_LIST['vendors'][vendor]['deviceStorageDisclosureUrl']
                with urllib.request.urlopen(disclosure_url) as url:
                    disclosure = json.load(url)
                disclosed_cookies = disclosure['disclosures']
                new_disclosure = { vendor : disclosed_cookies }
                STORAGE_DISCLOSURES.update(new_disclosure)
                finished = True
            except Exception as e:
                attempts += 1
                if ( attempts == MAX_RETRIES ) :
                    print(f"[DEB] could not retrieve the cookie disclosure for " + 
                          f"vendor {vendor}")
                    if ( args.debug ) :
                        print(f"\n[DEB] errormessage: \n{e} for url {disclosure_url}\n")
                
    else :
        # Disclosure already found in memory
        disclosed_cookies = STORAGE_DISCLOSURES[vendor]
    return disclosed_cookies

'''
Function to assess AdTech vendors' compliance with the TCF. Based on certain 
testcases we encode and inject appropriate TC strings, and then check if cookies
set by third parties are compliant to the consent encoded in the TC string.
'''
def assess_Vendor(driver, cmpID, mechanism, identifier, domain, prefix, suffix) :
    assessment_result = ""
    incremented_undisclosed_cookie = False
    incremented_violating_vendor = False
    incremented_violating_purpose = False
    incremented_failed_injection = False
    #TODO: keep track of unresolved cookies (incl domein)
    if ( args.debug ) : print(f"\n[DEB] Starting Vendor assessment")
    for testcase in TESTCASES['testcases'] :
        if ( args.debug ) :
            print(f"\n[DEB] running testcase {testcase['name']}")
        attempts = 0
        finished = False
        allowed_purposes = "all"
        if ( testcase['purposes'] == "none" ) :
            allowed_purposes = [ ]
        elif ( testcase['purposes'] != "all" ) :
            allowed_purposes = testcase['purposes']

        allowed_vendors = "all"
        if ( testcase['vendors'] == "none" ) :
            allowed_vendors = [ ]
        elif ( testcase['vendors'] != "all" ) :
            allowed_vendors =  testcase['vendors']

        while ( attempts < MAX_RETRIES and not finished ) :
            try: 
            # Restart driver, since on some websites removing cookies and 
            # clearing Local Storage does not reset given consent...
                stop_driver(driver)
                driver = configure_crawler()
                navigate_to_url(driver, domain)

                # Encode a TCstring to inject
                TCstring = get_TCstring(cmpID, testcase['purposes'], testcase['vendors'])

                if ( args.debug ) :
                    print(f"[DEB] injecting TC string:\n      {TCstring}")

                # Wrap TCstring with prefix and suffix
                TCstring_wrapped = f"{prefix}{TCstring}{suffix}"

                # Inject TCstring
                if ( mechanism == "cookie" ) :
                    inject_TC_string_cookie(driver, TCstring_wrapped, identifier, domain)

                elif (mechanism == "LS" ) :
                    inject_TC_string_LS(driver, TCstring_wrapped, identifier, domain)

                # Reload page
                driver.refresh()
                time.sleep(2 * TIME_FACTOR)

                # Check if injection was successful
                if ( not check_if_injected_matches_returned(driver, TCstring) ) :
                   if ( not incremented_failed_injection ) :
                       increment_failed_injection()
                       incremented_failed_injection = True

                   if ( args.debug ) :
                       print(f"[ERR] injection might have failed, injected string " +
                             F"was not exactly returned by __tcfapi. ({domain})") 
                   finished = True

                # Retrieve all third party cookies using BiDi, and check for 
                # each if the registered purpose matches the injected consent
                third_party_cookies_present = False
                cookies_json = driver.execute_cdp_cmd('Network.getAllCookies', {})
                for cookie in cookies_json['cookies'] :
                    parsed_cookie = json.loads(json.dumps(cookie))
                    # If domain is not current url (ends with, to include 
                    # subdomains), and value longer than minimum value, try to 
                    # find the cookie disclosure in the gvl, try to find the 
                    # identifier in the disclosure, and check if purposes match 
                    # with injected string 

                    # We could also check the max age to identify tracking cookies
                    if ( len(parsed_cookie['value']) > 10 and ( not parsed_cookie['domain'].endswith(domain) ) ) : 
                        third_party_cookies_present = True

                        disclosed_purposes_and_vendor = get_purposes_from_GVL(parsed_cookie['domain'], parsed_cookie['name'], domain)
                        disclosed_purposes = disclosed_purposes_and_vendor[0]
                        vendor = disclosed_purposes_and_vendor[1]
                        violating_purposes = [ ]
                        if ( allowed_purposes != "all" ) :
                            # Check for each disclosed purpose that this purpose
                            # is allowed according to our injected TC string
                            for purpose in disclosed_purposes :
                                if ( purpose not in allowed_purposes ) :
                                    violating_purposes.append(purpose)
                        if ( len(violating_purposes) > 0 ) :
                            print(f"[!!!] Cookie with id '{parsed_cookie['name']}' " +
                                  f"and domain '{parsed_cookie['domain']}' is set " + 
                                  "while it is disclosed to require purposes that " +
                                  f"are not consented to: {violating_purposes}" +
                                  f"({domain})")
                            # Add to results for output
                            assessment_result = f"{assessment_result} cookie " + \
                                         f"'{parsed_cookie['name']}, with domain " + \
                                         f"{parsed_cookie['domain']} set with " + \
                                         "violating purpose;"
                            if ( not incremented_violating_purpose ) :
                                increment_violating_purpose()
                                incremented_violating_purpose = True

                        if ( allowed_vendors != "all" ) :
                            # Check if the vendor, if it is found in the GVL, 
                            # that set this cookie is allowed in our injected 
                            # TC string
                            if ( vendor != 0 and ( allowed_vendors == "none" or vendor not in allowed_vendors )) :
                                print(f"[!!!] Cookie with identifier " + 
                                      f"'{parsed_cookie['name']}' and domain " + 
                                      f"'{parsed_cookie['domain']}' is set, while " + 
                                      f"it's vendor with id '{vendor}' was not " +
                                      "consented to in our injected TC string " + 
                                      f"({domain}).")
                            # Add to results for output
                            assessment_result = f"{assessment_result} cookie " + \
                                          f"'{parsed_cookie['name']}' with domain " + \
                                          f"{parsed_cookie['domain']} set with " + \
                                          "violating vendor;"
                            if ( not incremented_violating_vendor ) :
                                increment_violating_vendor()
                                incremented_violating_vendor = True


                if ( not third_party_cookies_present and args.debug ) : 
                    print(f"[DEB] No Third party cookies with length greater " + 
                          "than 10 found")
                finished = True

            except Exception as e: 
                if ( args.debug ) :
                    print(f"[DEB] Exception during Vendor assessment for cookie " + 
                          f"{parsed_cookie['name']} from domain {parsed_cookie['domain']}")
                attempts += 1

    return assessment_result

'''
Function to write the results of detection and assesment of a single URL to a 
file, appending one line if the file already exists
'''
def write_to_output(url, storage_mechanism, cookie_id, cmp_id, additional_data, URL_encoding, prefix, suffix,injection_success,CMP_assessment,vendor_assessment) :
    threadLock = threading.Lock()
    # Only store the pressence of prefix and suffix, since the value can be 
    # pages long
    if ( not prefix == "" ) :
        prefix = "prefix"
    if ( not suffix == "" ) :
        suffix = "suffix"
    with threadLock :
        output_file = ( args.output )
        if ( additional_data ) :
            add_data = "add_data"
        else : 
            add_data = ""
        if ( URL_encoding ) :
            url_encoded = "url_enc"
        else :
            url_encoded = ""
        # Development: if output file is /dev/tty: dont write output file headers
        if ( not os.path.isfile(output_file) and output_file != "/dev/tty" ) :
           # First time writing to output file: write file headers
           file = open(output_file, "w")
           file.write(f"#output file from Consent Injection ran at {starttime}\n")
           file.write("#format: url,storage location,key,CMP identifier,other " + 
                      "data in cookie/LS value,URL encoded,prefix,suffix,CMP " + 
                      "assessment results,Vendor assessment results\n")
           file.close()
        file = open(output_file, "a")
        file.write(f"{url},{storage_mechanism},{cookie_id},{cmp_id},{add_data}," + 
                   f"{url_encoded},{prefix},{suffix},{injection_success}," + 
                   f"{CMP_assessment},{vendor_assessment}\n")
        file.close()

'''
function to display the script's statistical resuls when it is finished or aborted
'''
def print_results() :
    endtime = datetime.datetime.now()
    
    print("\n\nDetection results: \n" +
          f"Number of websites tested: {total_tested}. \n" +
          f"Detected TCF implementation on {count_TCF_detections} websites. \n" +
          f"On {count_cookie_identifiers_detected} of these the TC string storage " +
          "was found.")

    if ( not args.detectOnly ) :
        no_output = True
        print(f"\nCMP assesment results:") 

        if ( consent_before_interaction != 0 ) :
            print(f"On {consent_before_interaction} out of " + 
                  f"{count_cookie_identifiers_detected} websites the CMP set a " + 
                  "TCstring with consent for cookies before user interaction " + 
                  "with a cookie dialog")
            no_output = False

        if ( injected_string_not_returned != 0 ) :
            print(f"On {injected_string_not_returned} out of " + 
                  f"{count_cookie_identifiers_detected} websites the CMP did not " +
                  "return the injected TCstring, but one with consent for vendors " + 
                  "and purposes, which could mean a failed injection, or non-" + 
                  "compliant CMP implementation")
            no_output = False
        if ( failed_injection != 0 ) :
            print(f"On {failed_injection} websites we failed to successfully " + 
                  "inject a Consent String") 
            no_output = False
        if ( no_output ) :
            print(f"No findings to report")

        print(f"\nVendor assesment results: ")
        no_output = True
        if ( violating_vendor != 0 ) :
            print(f"On {violating_vendor} websites a vendor placed a third-party" + 
                  " cookie while constent was not injected for it.")
            no_output = False
        if ( violating_purpose != 0 ) :
            print(f"On {violating_purpose} websites cookies were placed with a " + 
                  "purpose for which consent was not injected.")
            no_output = False
        if ( vendor_not_in_gvl != 0 ) :
            print(f"In total {vendor_not_in_gvl} cookie(s) were placed for which " + 
                  "no vendor was found in the GVL.")
            no_output = False
        if ( undisclosed_cookie != 0 ) :
            print(f"In total {undisclosed_cookie} cookies were placed for which " + 
                  "the identifier was not found in the disclosure of its vendor")
        if ( no_output ) :
            print(f"No findings to report")

    print(f"\n{count_TCF_non_detections} websites did not implement the TCF. \n" + 
          f"{filtered_out} domains were deemed unsafe or inappropriate by DNS " + 
          "resolvers \n" + 
          f"{errors} website visits resulted in an error.")
 
    print(f"Runtime: {endtime - starttime}")

'''
Main function of each worker thread, that handles the visiting of an individual
webpage, and do all nessecary steps of detecting an implementation of the TCF, 
assessing CMPs and Vendors when instructed
'''
def worker_main(url) :
    driver = configure_crawler()

    if ( args.debug ) : print(f"\n[DEB] Attempting to detect TCF on {url}")   
    domain = remove_path(url)
    URL_passed_filter = filter_unsafe_domain(domain)

        
    if ( URL_passed_filter and detect_tcf(driver, url) ) :
        TCstring_during_detection = ""
        interaction_success = interact_dialog_accept_all(driver, url)

        #some sites navigate away to subscription page, navigate back if needed
#        if ( domain != driver.current_url) : 
#            navigate_to_url(driver, domain) 
#        print("sleeping")
#        time.sleep(50 * TIME_FACTOR)

        storage_mechanism = "unk"
        detect_TC_in_cookies = detect_TCstring_cookie(driver, domain)

        Storage_identifier = detect_TC_in_cookies[0]
        additional_data = detect_TC_in_cookies[1]
        URL_encoding = detect_TC_in_cookies[2]
        prefix = detect_TC_in_cookies[3]
        suffix = detect_TC_in_cookies[4]
        TCstring_during_detection = detect_TC_in_cookies[5]

        if ( not interaction_success ) : 
            # Failed to interact with cookie dialog. A found TC string is the 
            # default string before interaction. Using this for CMP assessment
            # will lead to a false positive server-side mechanism detection. 
            # Instead we will encode a reject-all string during CMP assessment.
            TCstring_during_detection = ""

        if ( Storage_identifier == "" ) :
            detect_TC_in_LS = detect_TCstring_in_Local_Storage(driver, url)
            Storage_identifier = detect_TC_in_LS[0]
            additional_data = detect_TC_in_LS[1]
            URL_encoding = detect_TC_in_LS[2]
            prefix = detect_TC_in_LS[3]
            suffix = detect_TC_in_LS[4]
            TCstring_during_detection = detect_TC_in_LS[5]
            if ( Storage_identifier != "" ) :
                storage_mechanism = "LS"
        else :
            storage_mechanism = "cookie"
        if ( Storage_identifier == "" and ( args.verbose or args.debug )) : 
            print("[ERR] No TCString found in cookies or Local Storage, could " + 
                  f"indicate server-side storage. Unable to proceed with " +
                  f"assessment ({domain})")
        CMP_identifier = identify_CMP(driver)
        
        # If the TCstring storage has been found, and not running with 
        # detectOnly, start assessment of the CMP
        CMP_assessment_result = ("", False)
        vendors_assessment_result = ""
        if ( not Storage_identifier == "" and not args.detectOnly ) :

            CMP_assessment_result = assess_CMP(driver, CMP_identifier, storage_mechanism, Storage_identifier, url, prefix, suffix, TCstring_during_detection)

            # Only proceed with vendor assessment if Consent String injection 
            # was succesfull for this CMP
            if ( CMP_assessment_result[1] ):
                vendors_assessment_result = assess_Vendor(driver, CMP_identifier, storage_mechanism, Storage_identifier, url, prefix, suffix)
            else :
                if ( args.debug ) :
                    print(f"[DEB] Skipped Vendor assessment since Consent " + 
                          "Injection seems to have failed.") 

        if ( args.output != None ) :
            # Write all collected data and findings to output file
            write_to_output(url,storage_mechanism,Storage_identifier,CMP_identifier,additional_data,URL_encoding,prefix,suffix,f"Injection successful: {CMP_assessment_result[1]}",CMP_assessment_result[0],vendors_assessment_result)
    increment_total_tested()
    stop_driver(driver)

'''
Function to create a folder in which screenshots can be saved
'''
def create_screenshot_folder() :
    global screenshot_folder
    screenshot_folder = "screenshots_" + starttime.strftime("%d-%m-%Y_%H:%M:%S")
    if not os.path.exists(screenshot_folder):
        os.makedirs(screenshot_folder)

'''
Function to take a screenshot of the scraped webpage. Useful for capturing 
unsupported cookie dialog buttons.
'''
def take_screenshot(driver, url) :
    try: 
        driver.save_screenshot(f"{screenshot_folder}/{url}.png")
        if ( args.debug ) : print(f"[DEB] screenshot saved in {screenshot_folder}" + 
                                  f"/{url}.png")
    except Exception as e :
        print("[ERR] Exception while taking screenshot ({url})")
        if ( args.debug ) : print(f"[DEB] Errormessage: \n {e}")

'''
Fuction to print the current status of the script
'''
def print_status(total_to_test) :
    cur_time = datetime.datetime.now()
    runtime = cur_time - starttime
    print(f"\n[STS] Progess: {total_tested}/{total_to_test}")
    print(f"[STS] Runtime: {runtime}\n")

'''
Function that runs in a thread to capture certain keypresses, to abort the script
or to display it's status. Keypresses are only registered when a browser window 
is in focus. 
'''
def keyboard_listener(total_to_test, stop_listening) :
    stop = False
    while ( not stop ) :
        with keyboard.Events() as events:
            try :
                event = events.get(10)
                # Pressing Space should print out status
                if event.key == keyboard.Key.space :
                    print_status(total_to_test)
                    time.sleep(1 * TIME_FACTOR)
                # Pressing Escape should gracefully abort the program
                if event.key == keyboard.Key.esc :
                    print("[STS] Aborting\n")
                    # Stop main thread
                    os.kill(os.getpid(), signal.SIGINT) 
                    stop = True
            except Exception:
                pass
        if stop_listening():
                break
 
'''
Main function that does some ground work before it starts worker threads that 
do the actual scraping and assessing
'''
def main() :
    global TCSTRING_MAGIC_HEADER
    global TCSTRING_REJECT_ALL
    global ACCEPT_STRINGS
    try:
        parse_command()
        validate_command()
        url_list = prepare_url_list()
        ACCEPT_STRINGS = prepare_accept_strings()
        total_to_test = len(url_list)
     
        if ( args.screenshot ) :
            create_screenshot_folder()
        MAX_THREADS = int(args.threads)

        TCSTRING_REJECT_ALL = encode_TC_string_online(1, "none", "none")
        TCSTRING_MAGIC_HEADER = TCSTRING_REJECT_ALL[:2]

        stop_listening = False

        thread_kbd = threading.Thread(target=keyboard_listener, args=(total_to_test,lambda : stop_listening))
        thread_kbd.start()
 
        active_threads = []
        for url in url_list :
             while ( not len(active_threads) < MAX_THREADS ) :
                for thread in active_threads :
                    if ( not thread.is_alive() ) :
                        thread.join(90)
                        active_threads.remove(thread)
             time.sleep(1 * TIME_FACTOR)
             thread = threading.Thread(target=worker_main, args=(url,))
             thread.start()
             active_threads.append(thread)
             time.sleep(0.1 * TIME_FACTOR)

        for thread in active_threads :
            thread.join(100 * TIME_FACTOR)
        stop_listening = True
    except KeyboardInterrupt :
        for thread in active_threads :
            thread.join(90 * TIME_FACTOR)

main()
print("[...] Waiting for last thread(s) to finish")
time.sleep(200 * TIME_FACTOR)

if ( args.screenshot and len(os.listdir(screenshot_folder)) == 0 ) :
    if ( args.debug ) : print("[DEB] removing screenshot folder, since no " + 
                             "screenshots were made" )
    os.rmdir(screenshot_folder)

print_results()
quit()
