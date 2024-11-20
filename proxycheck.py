#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ProxyCheck Script

Author: Roxana Schram (陈美, Chen Mei)
Copyright (c) 2024 Roxana Schram (陈美)
All rights reserved.

Description:
    This program fetches information for a given IP address using the proxycheck.io service.
    It also optionally allows the user to block the ASN associated with the IP in Cloudflare.
    The program is designed to work with an environment file ("env.gipc") from Global IPconnect's 
    Cloudflare DNS Manager to manage Cloudflare credentials.

Usage:
    proxycheck <IP_address>

Requirements:
    - Python 3.x
    - requests
    - An environment file at ~/env.gipc containing:
        CLOUDFLARE_API_KEY=<your_api_key>
        CLOUDFLARE_EMAIL=<your_email>
        CLOUDFLARE_ACCOUNT_ID=<your_account_id>
        PROXYCHECK_API_KEY=<proxycheck_api_key>

Third-party Services:
    - proxycheck.io API for retrieving IP information.
    - Cloudflare API for managing firewall rules.

These services are used under their respective terms of service.

Third-party Libraries Used:
    - requests: Licensed under the MIT License (https://github.com/psf/requests)

LICENSE
-------
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

1. Any modification of this software from the provided state must include attribution to the original author, 
   Roxana Schram (陈美), clearly stated in the modified version.

2. If someone modifies code from a modified version created by another person, they must also give credit to all 
   previous authors, including the original author, Roxana Schram (陈美). This chain of attribution must remain intact 
   regardless of how many modifications or derivative versions are made.

3. The above copyright notice and this permission notice shall be included in all copies or substantial 
   portions of the Software, including any third-party libraries and dependencies used by this software.

4. This software also uses components licensed under the MIT License, specifically `requests`. License information 
   for these libraries is available at the locations mentioned in the "Third-party Libraries Used" section of this file. 
   You must include these licenses with any distribution of this software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT 
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN 
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import sys
import requests
import os
import json
import hashlib
import time

def load_env_variables(file_path):
    """Loads environment variables from a file."""
    env_vars = {}
    try:
        expanded_path = os.path.expanduser(file_path)
        with open(expanded_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                key, value = line.strip().split('=')
                env_vars[key] = value
    except FileNotFoundError:
        print("Warning: Environment file '{}' not found. Blocking ASN will be disabled.".format(file_path))
    except Exception as e:
        print("Error reading environment file: {}".format(e))
    return env_vars

def load_cache():
    """Loads cached IP information from a file."""
    cache_file_path = os.path.expanduser("~/proxycheck_cache.json")
    if os.path.exists(cache_file_path):
        try:
            with open(cache_file_path, 'r') as cache_file:
                return json.load(cache_file)
        except Exception as e:
            print("Error reading cache file: {}".format(e))
    return {}

def save_cache(cache):
    """Saves IP information to a cache file."""
    cache_file_path = os.path.expanduser("~/proxycheck_cache.json")
    try:
        with open(cache_file_path, 'w') as cache_file:
            json.dump(cache, cache_file)
    except Exception as e:
        print("Error writing to cache file: {}".format(e))

def fetch_ip_info(ip, api_key, force_update=False):
    # Load cache and check if IP information is available and not expired
    cache = load_cache()
    current_time = time.time()
    if ip in cache and not force_update:
        cached_data = cache[ip]
        if current_time - cached_data['timestamp'] < 7 * 24 * 60 * 60:  # 7 days in seconds
            return cached_data['data']

    # If not cached or expired, fetch new data from proxycheck.io
    url = f"https://proxycheck.io/v2/{ip}"
    params = {
        'key': api_key,
        'tag': 'ProxyCheck_CLI',
        'vpn': '1',
        'asn': '1',
        'node': '1'
    }
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        ip_info = response.json()

        # Update cache with new data
        cache[ip] = {
            'timestamp': current_time,
            'data': ip_info
        }
        save_cache(cache)

        return ip_info
    except requests.RequestException as e:
        print("Error fetching data from proxycheck.io: {}".format(e))
        sys.exit(1)

def parse_ip_info(ip, ip_info, env_vars):
    if ip_info and ip in ip_info:
        info = ip_info[ip]
        results = []

        # Add IP information summary
        results.append("")  # Add a blank line before the results
        results.append(f"IP Details: {ip}")

        # Extracting specific fields
        fields = {
            "ASN": "asn",
            "Range": "range",
            "Provider": "provider",
            "Organisation": "organisation",
            "Continent": "continent",
            "Country": "country",
            "Region": "region",
            "City": "city",
            "Postal Code": "postcode",
            "Latitude": "latitude",
            "Longitude": "longitude",
            "Proxy": "proxy",
            "Type": "type"
        }

        for label, key in fields.items():
            value = info.get(key, 'N/A')
            results.append(f"{label}: {value}")

        results.append(" " * 80)  # Add an empty line of spaces
        results.append("-" * 80)  # Separator line

        # Save log file to user's home directory
        log_file_path = os.path.expanduser("~/proxycheck_results.txt")
        try:
            with open(log_file_path, 'a', encoding='utf-8') as file:
                file.write('\n'.join(results) + '\n\n')
        except Exception as e:
            print("Error writing to log file: {}".format(e))

        # Also print the output to the console
        print('\n'.join(results))

        # Only prompt the user to block ASN if Cloudflare credentials are available
        if "asn" in info and env_vars:
            block_asn = input("\nDo you want to block ASN {} in Cloudflare? (y/n, default: n): ".format(info['asn'])).strip().lower()
            if block_asn in ['y', 'yes']:
                asn_numeric = ''.join(filter(str.isdigit, info["asn"]))
                block_asn_in_cloudflare(asn_numeric, env_vars)
    else:
        print("Could not retrieve information for the IP address: {}".format(ip))

def block_asn_in_cloudflare(asn, env_vars):
    api_key = env_vars.get("CLOUDFLARE_API_KEY")
    email = env_vars.get("CLOUDFLARE_EMAIL")
    account_id = env_vars.get("CLOUDFLARE_ACCOUNT_ID")

    if not api_key or not email or not account_id:
        print("Missing Cloudflare API credentials.")
        return

    # Cloudflare API endpoint
    url = "https://api.cloudflare.com/client/v4/accounts/{}/firewall/access_rules/rules".format(account_id)

    # Create the request payload
    data = {
        "mode": "block",
        "configuration": {
            "target": "asn",
            "value": asn  # Numeric part only
        },
        "notes": "Datacenter ASN"
    }

    # Set the request headers
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }

    # Make the POST request to block the ASN
    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 200:
        print("Successfully blocked ASN {} in Cloudflare.".format(asn))
    else:
        print("Failed to block ASN {}. Response: {}".format(asn, response.text))

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: proxycheck <IP_address> [-u]")
        sys.exit(1)

    ip = sys.argv[1]
    # Load environment variables from the user's home directory
    env_vars = load_env_variables("~/env.gipc")

    # Fetch IP information using proxycheck.io
    api_key = env_vars.get("PROXYCHECK_API_KEY")
    if not api_key:
        print("Error: PROXYCHECK_API_KEY is missing in the environment file.")
        sys.exit(1)

    force_update = '-u' in sys.argv
    ip_info = fetch_ip_info(ip, api_key, force_update)
    parse_ip_info(ip, ip_info, env_vars)

if __name__ == "__main__":
    main()
