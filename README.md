# WPHunter
Wordpress Hunting Bruteforce Tool with Google Dork

![](https://github.com/CalfCrusher/WPHunter/blob/main/img/WPHunter.png)

### Features

-> Multiple dorks for Wordpress

-> WPSCAN (wpscan.com)

-> TOR support

-> Save passwords to db

### Usage

`$ git clone https://github.com/CalfCrusher/WPHunter/`

`$ cd WPHunter && pip3 install -r requirements.txt`

`$ python3 WPHunter.py`


### Note

If you get errors about googlesearch module try this:

`$ pip3 uninstall google googlesearch googlesearch-python search`

`$ pip3 install -r requirements.txt`

### TODO

.Adding more dorks for CVE

.Parse some know vulnerabilities and report them (without using api-token on wpscan)

### Disclaimer

I made this tool just for educational use only. I'm not responsible for the consequences of illegal use.
