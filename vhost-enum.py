#!/usr/bin/env python3
import argparse
import hashlib
import logging
import queue
import requests
import socket
import sys
import time
import threading
import urllib3


class CustomFormatter(logging.Formatter):

    err_fmt = "[-] %(msg)s"
    wrn_fmt = "[!] %(msg)s"
    dbg_fmt = "DEBUG: %(msg)s"
    info_fmt = "[+] %(msg)s"

    def __init__(self):
        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style='%')

    def format(self, record):
        format_orig = self._style._fmt
        if record.levelno == logging.DEBUG:
            self._style._fmt = CustomFormatter.dbg_fmt
        elif record.levelno == logging.INFO:
            self._style._fmt = CustomFormatter.info_fmt
        elif record.levelno == logging.ERROR:
            self._style._fmt = CustomFormatter.err_fmt
        elif record.levelno == logging.WARNING:
            self._style._fmt = CustomFormatter.wrn_fmt
        result = logging.Formatter.format(self, record)
        self._style._fmt = format_orig
        return result


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--wordlist", help="The wordlist to use", default="./vhosts.txt", required=False)
    parser.add_argument("-s", "--tls", action='store_true', help="Use HTTPs")
    parser.add_argument("-i", "--ip", help="The ip of the host", required=True)
    parser.add_argument("-p", "--port", help="A custom port to use")
    parser.add_argument("-d", "--domain", help="The domain to use", required=True)
    parser.add_argument('-b', "--baseline", help="The baseline subdomain to use", default="www")
    parser.add_argument('-t', "--threads", default=1, help="Number of threads to use", type=int)
    parser.add_argument('-v', "--verbose", action='store_true', help="Set loglevel to DEBUG")
    return parser.parse_args()


def new_getaddrinfo(*args):
    if args[0] in dns_cache:
        return prv_getaddrinfo(dns_cache[args[0]], *args[1:])
    else:
        return prv_getaddrinfo(*args)


def override_dns(domain, ip):
    dns_cache[domain] = ip


def get_site(ip, host, subdomain, tls, custom_port, http_session):
    url = f"{subdomain}.{host}"
    if tls:
        if custom_port is None:
            url = f"https://{url}:443"
        else:
            url = f"https://{url}:{custom_port}"
    else:
        if custom_port is None:
            url = f"http://{url}:80"
        else:
            url = f"http://{url}:{custom_port}"
    try:
        response = http_session.get(url, verify=False)
    except requests.exceptions.SSLError:
        logging.error(f"{url} was requested but SSL error occurred (is the site using TLS?).")
        return None, None
    except requests.exceptions.ConnectionError as error:
        logging.error(f"Failed to connect to {ip}.\n{error}")
        return None, None
    except requests.exceptions.InvalidURL:
        logging.error(f"Url {url} is invalid.")
        return None, None
    if response.status_code == 200:
        length = len(response.content)
        hash_object = hashlib.sha256(response.content)
        hash_value = hash_object.hexdigest()
        return length, hash_value
    else:
        logging.error(f"Request to {url} failed.")
        return None, None


def consume_words(wordlist_queue, ip, port, tls, domain, l_baseline, h_baseline, result_list):
    http_session = requests.session()
    while not wordlist_queue.empty():
        word = wordlist_queue.get()
        length, digest = get_site(ip, domain, word.rstrip('\n'), tls, port, http_session)
        if length is not None and digest is not None:
            if length == l_baseline or digest == h_baseline:
                logging.debug(f"{word}.{domain} returns 200, but the content seems to be the same"
                              f" as the one of main site.")
            else:
                logging.info(f"{word}.{domain} returns 200 and seems a different site")
                result_list.append(f"{word}.{domain}")


def __generate_dns_cache(words_list, domain, ip):
    logging.info("Generating DNS cache to use...")
    for word in words_list:
        url = f"{word}.{domain}"
        override_dns(url, ip)


def __get_wordlist(wordlist_file):
    try:
        with open(wordlist_file) as fp:
            content = fp.read()
            words = content.split('\n')
    except FileNotFoundError:
        logging.error(f"File {wordlist_file} does not exist. Aborting.")
        exit(1)
    # Removes empty lines
    words = filter(None, words)
    # Removes duplicates
    words = set(words)
    return words


def __get_wordlist_queue(words_list):
    logging.info("Generating wordlist...")
    words_queue = queue.Queue()
    for w in words_list:
        words_queue.put(w)
    logging.info(f"Loaded {words_queue.qsize()} words.")
    return words_queue


def main():
    args = get_args()
    if args.verbose:
        logging.root.setLevel(logging.DEBUG)
    else:
        logging.root.setLevel(logging.INFO)
    wordlist = args.wordlist
    tls = args.tls
    ip = args.ip
    port = args.port
    domain = args.domain
    baseline = args.baseline
    threads = args.threads
    words_list = __get_wordlist(wordlist)
    __generate_dns_cache(words_list, domain, ip)
    wordlist_queue = __get_wordlist_queue(words_list)
    l_baseline, h_baseline = get_site(ip, domain, baseline, tls, port, http_session=requests.session())
    if l_baseline is None or h_baseline is None:
        logging.error(f"Establishing baseline failed. Make sure that {baseline}.{domain} exists "
                      f"and that you are using the correct port.")
        exit(1)
    logging.info(f"Established baseline: {baseline}.{domain} returns a "
                 f"page of {l_baseline} bytes and with hash {h_baseline}.")
    confirmed = list()
    threads_list = list()
    logging.info(f"Spawning {threads} thread(s)...")
    timestamp_start = time.time()
    for i in range(threads):
        worker = threading.Thread(target=consume_words, args=(wordlist_queue, ip, port, tls, domain, l_baseline,
                                                              h_baseline, confirmed))
        threads_list.append(worker)
        worker.start()
    for thread in threads_list:
        thread.join()
    logging.info(f"Job completed in {time.time()-timestamp_start} seconds.")
    if len(confirmed) > 0:
        logging.info("The following virtualhost were discovered:")
        for site in confirmed:
            print(f"* {site}")
    else:
        logging.warning("No virtualhosts were discovered.")


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    dns_cache = {}
    prv_getaddrinfo = socket.getaddrinfo
    socket.getaddrinfo = new_getaddrinfo
    formatter = CustomFormatter()
    hdlr = logging.StreamHandler(sys.stdout)
    hdlr.setFormatter(formatter)
    logging.root.addHandler(hdlr)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    main()
