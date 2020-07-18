## Vhost-enum

This is a simple Python script (requires Python 3.6+) used to enumerate virtualhosts.
The main use-case is during CTFs or HackTheBox machines where different sites are served based on the virtualhosts.

For example:

```
# Serves default page
www.example.com
# Serves hidden site
blog.example.com
```

Usually, in order to detect such sites it is necessary to add every host to the `/etc/hosts` file, or do some scripting
with `curl` (using the `--resolve` option).

This script makes it slightly simpler.

## How does it work?

The help of the script says it all:

```bash
python3 vhost-enum.py -h                                                     
usage: vhost-enum.py [-h] [-w WORDLIST] [-s] -i IP [-p PORT] -d DOMAIN
                     [-b BASELINE] [-t THREADS]

optional arguments:
  -h, --help            show this help message and exit
  -w WORDLIST, --wordlist WORDLIST
                        The wordlist to use
  -s, --tls             Use HTTPs
  -i IP, --ip IP        The ip of the host
  -p PORT, --port PORT  A custom port to use
  -d DOMAIN, --domain DOMAIN
                        The domain to use
  -b BASELINE, --baseline BASELINE
                        The baseline subdomain to use
  -t THREADS, --threads THREADS
                        Number of threads to use
```

The `-w` options is to specify a newline separated list of words to use a subdomains. This can include also
sub-subdomains (e.g., `dev.test`).

The `-s` option is used to specify whether we want TLS or not. If the options is set, the requests will be made to port
`443`, otherwise they will go to port `80`, unless `-p` is specified.

The `-i` option is used to specify the IP to use for the DNS resolution (e.g., `10.10.10.1`).

The `-p` option is used to specify a custom port to use, for example `8080`.

Please make sure that `-s` and `-p` options are used sensibly (requesting HTTPs to HTTP port or vice versa will obviously fail).

The `-d` option is used to specify the main domain name to use (e.g., `machine.htb`).

The `-b` option is used to specify the baseline subdomain, so one domain that we already know exists (defaults to `www`).

The `-t` option is used to specify how many threads to use as workers (to make requests).

The login is the following:

* All requests will skip DNS resolution, that will be overridden with the IP specified. 
* A request to baseline.domain:port (or `80`/`443` depending on `-s` if `-p` is not specified) will be performed. The
length and hash of the response content will be saved and used to compare the response coming from other virtualhosts.
* A request to word.domain:port (or `80`/`443` depending on `-s` if `-p` is not specified) will be performed, for every `word` in
the wordlist.

At this point, the script makes the following choices:

* If the request returned 200, but with the same length or hash as the baseline, this is considered to be the same page
and therefore the corresponding `word` won't be validated (this is the case for a `default` backend in Haproxy for example,
that will respond to every request that doesn't match other ACLs). The reason why the length is also used is to try to catch
pages where some small content changes (maybe a timestamp), but the page is basically the same (so hash won't match).
* If the request returned 200 and the hash and length of the response are different from the baseline, the virtualhost will be
added to the discovered ones and will be reported.

### Note about the wordlists

The wordlist included by default with this repo is for test purposes only (still faster to dump ideas there that in hosts file). 
In order to find appropriate lists, it might be possible to use [Cewl](https://github.com/digininja/CeWL) o generate
a custom one or use some generic list from [seclists](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/bitquark-subdomains-top100000.txt) or similar projects.

## Installation

The installation is pretty straightforward

Clone the repo and install requirements (the only package required is requests).
```bash
git clone https://github.com/sudneo/vhost-enum
cd vhost-enum
pip3 install -r requirements.txt
chmod +x vhost-enum.py
./vhost-enum.py -h
# Or, in alternative
python3 vhost-enum.py -h
```