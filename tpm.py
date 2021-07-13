#!/usr/bin/env python3
# pylint: disable=no-name-in-module

"""
This program will display TPM records using the TPM API
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import configparser
import fcntl
import json
import os
import pprint
import sys
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import Terminal256Formatter
import re
import requests

def cache_load():
    """ Return the list of record dicts from the json cache file """
    cache_file = get_path("cache_file")
    if not os.path.exists(cache_file):
        raise FileNotFoundError()
    with open(cache_file, "r+") as jabber: # fcntl lock doesn't work without write
        try:
            fcntl.lockf(jabber, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as err:
            die(5, "Cache file lock: {}".format(err))
        ret = json.load(jabber)
        fcntl.lockf(jabber, fcntl.LOCK_UN)
        return ret

def cache_refresh():
    """ Download the TPM record list and place it into the cache file """
    cache_file = get_path("cache_file")
    with open(cache_file, "w") as jabber:
        try:
            fcntl.lockf(jabber, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as err:
            die(5, "Cache file lock: {}".format(err))
        json.dump(tpm_get_list(), jabber)
        fcntl.lockf(jabber, fcntl.LOCK_UN)

def die(code, msg):
    """ Terminate program (exit status, message) """
    print(msg, file=sys.stderr)
    print("Exiting.", file=sys.stderr)
    sys.exit(code)

def find_match(record, patterns):
    """
    Searches through a TPM record dict for string items
    and returns True if a pattern in patterns list is found
    """
    for key, val in record.items():
        if not isinstance(val, str):
            continue
        for i in patterns:
            if settings["regex"]:
                if re.match(i.lower(), val.lower()):
                    return True
            else:
                if i.lower() in val.lower():
                    return True
    return False

def get_path(filename):
    return os.path.join(settings["tpm_dir"], settings[filename])

def parse_conf():
    """ Parse the config file and populate the settings dict """
    conffile = get_path("conf_file")
    if not os.path.exists(conffile):
        print("Warning: Config file does not exist.", file=sys.stderr)
        return
    config = configparser.ConfigParser()
    config.read(conffile)
    cred_ini_section = "credentials"
    if cred_ini_section in config.sections():
        for setting in ("username", "password"):
            if setting in config[cred_ini_section]:
                settings[setting] = config[cred_ini_section][setting]
    tpm_ini_section = "tpm"
    if "tpm" in config.sections():
        if "api_url" in config[tpm_ini_section]:
            settings["api_url"] = config[tpm_ini_section]["api_url"]
        for setting in ("brief", "nocolor"):
            if setting in config[tpm_ini_section]:
                settings[setting] = bool(config[tpm_ini_section][setting])

def password_fmt(password):
    """
    Format a password record dict appropriately
    Ommiting fields and getting names from sub-dicts
    """
    if settings["all_fields"]:
        return password
    ret = dict()
    for key, val in password.items():
        pw_added = False
        for i in ("project", "updated_by"):
            if key == i:
                if val:
                    ret[i] = val["name"]
                    pw_added = True
                    break
                else:
                    ret[i] = val
        if pw_added:
            continue
        if key in settings["show_fields"]:
            ret[key] = val
    return ret

def print_password(password):
    output = ""
    if settings["brief"]:
        for i in ("name", "username", "password"):
            output += f"{i}: {password[i]}\n"
        output += "---"
    else:
        output = pprint.PrettyPrinter().pformat(password)

    if settings["nocolor"] or settings["brief"]:
        print(output)
    else:
        print(highlight(output, PythonLexer(), Terminal256Formatter()))

def process_args(args):
    """ Process args, update settings dict when needed """
    if args.refresh:
        cache_refresh()
        quit()
    if not args.pattern:
        quit()
    if args.user:
        settings["username"] = args.user
    if args.password:
        settings["password"] = args.password
    for i in ("username", "password"):
        if not settings[i]:
            die(2, "{} is undefined.".format(i))
    settings["all_fields"] = args.allfields
    if args.regex:
        settings["regex"] = True
    if args.threads:
        try:
            settings["max_threads"] = int(args.threads)
            if settings["max_threads"] <= 0:
                raise ValueError()
        except ValueError:
            die(6, "{} is not a valid thread count (--threads)".format(args.threads))
    if args.url:
        settings["api_url"] = args.url
    elif not settings["api_url"]:
        die(5, "No TPM API URL defined")
    if args.nocolor:
        settings["nocolor"] = True
    if args.brief:
        settings["brief"] = True

def tpm_api_call(url):
    """ Make a call to url and return a requests object """
    headers = {"Content-Type": "application/json; charset=utf-8"}
    return requests.get(url, \
                        auth=(settings["username"],  \
                        settings["password"]),       \
                        headers=headers)

def tpm_get_list():
    """ Return a list of TPM password record dicts, using pagination concurrently. """
    count_url = settings["api_url"] + "/passwords/count.json"
    count_info = tpm_api_call(count_url).json()
    page_count = count_info["num_pages"]
    url_list  = list()
    for i in range(1, page_count + 1):
        url_list.append(settings["api_url"] + "/passwords/page/{}.json".format(i))
    ret = list()
    with ThreadPoolExecutor(max_workers=settings["max_threads"]) as executor:
        for page in executor.map(tpm_api_call, url_list):
            ret.extend(page.json())
    return ret

def tpm_get_password(passid):
    """ Return a TPM record dict with the password """
    return tpm_api_call(settings["api_url"] + \
                        "/passwords/{}.json".format(passid)).json()

settings = {
    "all_fields": False,
    "api_url": "",
    "brief": False,
    "cache_file": "cache.json",
    "conf_file":  "settings.ini",
    "copy": True,
    "max_threads": 16,
    "nocolor": False,
    "password": "",
    "regex": False,
    "show_fields": ("access_info", \
                    "email", \
                    "name", \
                    "notes", \
                    "password", \
                    "project", \
                    "updated_by", \
                    "updated_on", \
                    "username"),
    "tpm_dir": os.path.expanduser("~/.tpm"),
    "username": ""
}

parser = argparse.ArgumentParser(description="Get passwords from Team Password Manager.")
parser.add_argument("pattern", nargs='*')
parser.add_argument("--user", "-u", help="TPM user to authenticate as")
parser.add_argument("--password", "-p", help="TPM password for authentication")
parser.add_argument("--url", "-l", help="TPM API URL")
parser.add_argument("--allfields", "-a", help="Print all TPM record fields", action="store_true")
parser.add_argument("--regex", "-r", help="Interpret PATTERNS as Perl-compatible regular expressions (PCREs).", \
                    action="store_true")
parser.add_argument("--threads", "-t", help="Maximum number of workers for concurrent API calls. Default: {}".format(settings["max_threads"]))
parser.add_argument("--refresh", help="Update the TPM cache and quit", action="store_true")
parser.add_argument("--nocolor", help="Do not use colourized output", action="store_true")
parser.add_argument("--brief", help="Print a simpler, brief output", action="store_true")
args = parser.parse_args()

parse_conf()
process_args(args)
if not sys.stdout.isatty():
    settings["nocolor"] = True
settings["api_url"] += "/index.php/api/v4"

matched_ids = list()
record_list = list()

try:
    record_list = cache_load()
except FileNotFoundError:
    die(4, "Cache file not found. Please run with --refresh first!")

for record in record_list:
    if find_match(record, args.pattern):
        matched_ids.append(record["id"])

if matched_ids:
    print("Found {} results...".format(len(matched_ids)))
else:
    print("No results found.\nTry updating the cache with --refresh?")
    quit()

with ThreadPoolExecutor(max_workers=settings["max_threads"]) as executor:
    for password in executor.map(tpm_get_password, matched_ids):
        print_password(password_fmt(password))
