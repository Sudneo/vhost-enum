#!/usr/bin/env python3
import argparse
import hashlib
import queue
import requests
import socket
import time
import threading
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
dns_cache = {}
prv_getaddrinfo = socket.getaddrinfo


# Override default socket.getaddrinfo() and pass ip instead of host
# if override is detected
def new_getaddrinfo(*args):
    if args[0] in dns_cache:
        return prv_getaddrinfo(dns_cache[args[0]], *args[1:])
    else:
        return prv_getaddrinfo(*args)


socket.getaddrinfo = new_getaddrinfo


# Capture a dict of hostname and their IPs to override with
def override_dns(domain, ip):
    dns_cache[domain] = ip


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--wordlist", help="The wordlist to use", default="./vhosts.txt", required=False)
    parser.add_argument("-s", "--tls", action='store_true', help="Use HTTPs")
    parser.add_argument("-i", "--ip", help="The ip of the host", required=True)
    parser.add_argument("-p", "--port", help="A custom port to use")
    parser.add_argument("-d", "--domain", help="The domain to use", required=True)
    parser.add_argument('-b', "--baseline", help="The baseline subdomain to use", default="www")
    parser.add_argument('-t', "--threads", default=1, help="Number of threads to use", type=int)
    return parser.parse_args()


def get_site(ip, host, subdomain, tls, custom_port, http_session):
    url = f"{subdomain}.{host}"
    override_dns(url, ip)
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
        print(f"\t[-] {url} was requested but SSL error occurred (is the site using TLS?).")
        return None, None
    except requests.exceptions.ConnectionError:
        print(f"\t[-] Failed to connect to {ip}.")
        return None, None
    except requests.exceptions.InvalidURL:
        print(f"\t[-] Url {url} is invalid.")
        return None, None
    if response.status_code == 200:
        length = len(response.content)
        hash_object = hashlib.sha256(response.content)
        hash_value = hash_object.hexdigest()
        return length, hash_value
    else:
        print(f"\t[-] Request to {url} failed.")
        return None, None


def get_wordlist_queue(wordlist_file):
    print("[+] Generating wordlist...")
    words_queue = queue.Queue()
    try:
        with open(wordlist_file) as fp:
            content = fp.read()
            words = content.split('\n')
    except FileNotFoundError:
        print(f"[-] File {wordlist_file} does not exist. Aborting.")
        exit(1)
    # Removes empty lines
    words = filter(None, words)
    # Removes duplicates
    words = set(words)
    for w in words:
        words_queue.put(w)
    print(f"[+] Loaded {words_queue.qsize()} words.")
    return words_queue


def consume_words(wordlist_queue, ip, port, tls, domain, l_baseline, h_baseline, result_list):
    http_session = requests.session()
    while not wordlist_queue.empty():
        word = wordlist_queue.get()
        length, digest = get_site(ip, domain, word.rstrip('\n'), tls, port, http_session)
        if length is not None and digest is not None:
            if length == l_baseline or digest == h_baseline:
                print(f"\t[!] {word}.{domain} returns 200, but the content seems to be the same as the one of main site.")
            else:
                print(f"\t[+] {word}.{domain} returns 200 and seems a different site")
                result_list.append(f"{word}.{domain}")


def main():
    args = get_args()
    wordlist = args.wordlist
    tls = args.tls
    ip = args.ip
    port = args.port
    domain = args.domain
    baseline = args.baseline
    threads = args.threads
    wordlist_queue = get_wordlist_queue(wordlist)
    l_baseline, h_baseline = get_site(ip, domain, baseline, tls, port, http_session=requests.session())
    if l_baseline is None or h_baseline is None:
        print(f"[-] Establishing baseline failed. Make sure that {baseline}.{domain} exists "
              f"and that you are using the correct port.")
        exit(1)
    print(f"[+] Established baseline: {baseline}.{domain} returns a "
          f"page of {l_baseline} bytes and with hash {h_baseline}.")
    confirmed = list()
    threads_list = list()
    print(f"[+] Spawning {threads} thread(s)...")
    timestamp_start = time.time()
    for i in range(threads):
        worker = threading.Thread(target=consume_words, args=(wordlist_queue, ip, port, tls, domain, l_baseline,
                                                              h_baseline, confirmed))
        threads_list.append(worker)
        worker.start()
    for thread in threads_list:
        thread.join()
    print(f"[+] Job completed in {time.time()-timestamp_start} seconds.")
    if len(confirmed) > 0:
        print("[+] The following virtualhost were discovered:")
        for site in confirmed:
            print(f"* {site}")
    else:
        print("[-] No virtualhosts were discovered.")


if __name__ == '__main__':
    main()

