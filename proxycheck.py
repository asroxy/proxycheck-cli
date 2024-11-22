#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ProxyCheck CLI
# Author: Roxana Schram (陈美, Chen Mei)
# Copyright (c) 2024 Roxana Schram (陈美)
# All rights reserved.
#
# Description:
# This program fetches information for a given IP address or email using the proxycheck.io service.
# It also optionally allows the user to block the ASN associated with the IP in Cloudflare.
# The program is designed to work with an environment file ("env.gipc") from Global IPconnect's
# Cloudflare DNS Manager to manage Cloudflare credentials.
#
# Usage:
# proxycheck <IP_address>
# proxycheck -e <email_address>
#
# Requirements:
# - Python 3.x
# - requests
# - An environment file at ~/env.gipc containing:
# CLOUDFLARE_API_KEY=<your_api_key>
# CLOUDFLARE_EMAIL=<your_email>
# CLOUDFLARE_ACCOUNT_ID=<your_account_id>
# PROXYCHECK_API_KEY=<proxycheck_api_key>
#
# Third-party Services:
# - proxycheck.io API for retrieving IP and email information.
# - Cloudflare API for managing firewall rules.
#
# Third-party Libraries Used:
# - requests: Licensed under the MIT License (https://github.com/psf/requests)
#
# LICENSE
# MIT License

import sys
import requests
import os
import json
import hashlib
import time

def load_env_variables(file_path):
    # 加载环境变量文件。
    # Loads environment variables from a file.
    env_vars = {}
    try:
        expanded_path = os.path.expanduser(file_path)
        with open(expanded_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                key, value = line.strip().split('=')
                env_vars[key] = value
    except FileNotFoundError:
        # 如果找不到环境文件，发出警告
        # Warning if the environment file is not found
        print("Warning: Environment file '{}' not found. Blocking ASN will be disabled.".format(file_path))
    except Exception as e:
        # 处理任何其他异常的错误
        # Error handling for any other exceptions
        print("Error reading environment file: {}".format(e))
    return env_vars

def load_cache():
    # 从文件加载缓存信息。
    # Loads cached information from a file.
    cache_file_path = os.path.expanduser("~/proxycheck_cache.json")
    if os.path.exists(cache_file_path):
        try:
            with open(cache_file_path, 'r') as cache_file:
                return json.load(cache_file)
        except Exception as e:
            # 处理读取缓存文件的问题
            # Error handling for issues with reading the cache file
            print("Error reading cache file: {}".format(e))
    return {}

def save_cache(cache):
    # 保存信息到缓存文件。
    # Saves information to a cache file.
    cache_file_path = os.path.expanduser("~/proxycheck_cache.json")
    try:
        with open(cache_file_path, 'w') as cache_file:
            json.dump(cache, cache_file)
    except Exception as e:
        # 处理写入缓存文件的问题
        # Error handling for issues with writing to the cache file
        print("Error writing to cache file: {}".format(e))

def fetch_ip_info_with_operator(ip, api_key, force_update=False):
    # 加载缓存并检查IP信息是否可用且未过期
    # Load cache and check if IP information is available and not expired
    cache = load_cache()
    current_time = time.time()
    if ip in cache and not force_update:
        cached_data = cache[ip]
        if current_time - cached_data['timestamp'] < 7 * 24 * 60 * 60:  # 7天的秒数
            # 如果缓存可用且未过期，则使用缓存数据
            # Use cached data if available and not expired
            print("Results fetched from cache.")
            return cached_data['data'], "cache"

    # 如果未缓存或已过期，从proxycheck.io获取新数据
    # If not cached or expired, fetch new data from proxycheck.io
    url = f"https://proxycheck.io/v2/{ip}"
    params = {
        'key': api_key,
        'tag': 'ProxyCheck_CLI',
        'vpn': '1',
        'asn': '1',
        'node': '1',
        'risk': '1'
    }
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        ip_info = response.json()

        # 确保操作员详细信息包含在缓存中
        # Ensure operator details are included in the cache
        if "operator" in ip_info.get(ip, {}):
            cache[ip] = {
                'timestamp': current_time,
                'data': ip_info
            }
        else:
            # 如果操作员详细信息不存在，则将其设置为None
            # If operator details are not present, set it to None
            ip_info[ip]["operator"] = None
            cache[ip] = {
                'timestamp': current_time,
                'data': ip_info
            }

        # 保存更新的缓存
        # Save updated cache
        save_cache(cache)

        print("Results fetched from Proxycheck.io.")
        return ip_info, "proxycheck"
    except requests.RequestException as e:
        # 处理proxycheck.io请求的问题
        # Error handling for issues with the proxycheck.io request
        print("Error fetching data from Proxycheck.io: {}".format(e))
        sys.exit(1)

def fetch_email_info(email, api_key):
    # 从proxycheck.io获取电子邮件信息
    # Fetch email information from proxycheck.io
    url = f"https://proxycheck.io/v2/{email}"
    params = {
        'key': api_key,
        'tag': 'ProxyCheck_CLI',
        'email': '1'
    }
    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        email_info = response.json()

        # 如果有可用的电子邮件信息，则显示
        # Display email information if available
        if email in email_info:
            info = email_info[email]
            print(f"\nEmail Details for {email}:")
            print(f"Disposable: {info.get('disposable', 'N/A')}\n")
        else:
            print(f"\nNo information found for the email: {email}\n")
    except requests.RequestException as e:
        # 处理proxycheck.io请求的问题
        # Error handling for issues with the proxycheck.io request
        print("Error fetching data from Proxycheck.io: {}".format(e))
        sys.exit(1)

def parse_ip_info(ip, ip_info, env_vars):
    # 解析并显示为IP地址检索到的信息
    # Parse and display information retrieved for an IP address
    if ip_info and ip in ip_info:
        info = ip_info[ip]
        results = []

        # 添加IP信息摘要
        # Add IP information summary
        results.append("")  # 在结果前添加一个空行
        results.append(f"IP Details: {ip}")

        # 提取要显示的特定字段
        # Extracting specific fields to display
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

        # 将字段值附加到结果中
        # Append field values to the results
        for label, key in fields.items():
            value = info.get(key, 'N/A')
            results.append(f"{label}: {value}")

        # 提取操作员和政策（如果有）
        # Extract operator and policies if available
        operator = info.get("operator", None)
        if operator:
            results.append("\nOperator Details:")
            results.append(f"Name: {operator.get('name', 'N/A')}")
            results.append(f"URL: {operator.get('url', 'N/A')}")
            results.append(f"Anonymity: {operator.get('anonymity', 'N/A')}")
            results.append(f"Popularity: {operator.get('popularity', 'N/A')}")
            results.append(f"Protocols: {', '.join(operator.get('protocols', []))}")
            
            # 提取和显示政策
            # Extract and display policies
            policies = operator.get("policies", {})
            results.append("\nPolicies:")
            for key, value in policies.items():
                results.append(f"{key.replace('_', ' ').capitalize()}: {value}")
        else:
            results.append("\nNo operator details found for this IP.")

        # 添加分隔符并将结果保存到日志文件
        # Add separators and save results to a log file
        results.append(" " * 80)  # 添加一行空格
        results.append("-" * 80)  # 分隔线

        # 将日志文件保存到用户的主目录
        # Save log file to user's home directory
        log_file_path = os.path.expanduser("~/proxycheck_results.txt")
        try:
            with open(log_file_path, 'a', encoding='utf-8') as file:
                file.write('\n'.join(results) + '\n\n')
        except Exception as e:
            # 处理写入日志文件的问题
            # Error handling for issues with writing to the log file
            print("Error writing to log file: {}".format(e))

        # 还将输出打印到控制台
        # Also print the output to the console
        print('\n'.join(results))

        # 仅当Cloudflare凭据可用时才提示用户阻止ASN
        # Only prompt the user to block ASN if Cloudflare credentials are available
        if "asn" in info and env_vars:
            block_asn = input("\nDo you want to block ASN {} in Cloudflare? (y/n, default: n): ".format(info['asn'])).strip().lower()
            if block_asn in ['y', 'yes']:
                asn_numeric = ''.join(filter(str.isdigit, info["asn"]))
                block_asn_in_cloudflare(asn_numeric, env_vars)
    else:
        # 如果无法检索到IP信息，则打印错误
        # Print error if IP information could not be retrieved
        print("Could not retrieve information for the IP address: {}".format(ip))

def block_asn_in_cloudflare(asn, env_vars):
    # 使用Cloudflare API阻止ASN
    # Block ASN in Cloudflare using the Cloudflare API
    api_key = env_vars.get("CLOUDFLARE_API_KEY")
    email = env_vars.get("CLOUDFLARE_EMAIL")
    account_id = env_vars.get("CLOUDFLARE_ACCOUNT_ID")

    if not api_key or not email or not account_id:
        # 如果缺少所需的Cloudflare凭据，则出错
        # Error if required Cloudflare credentials are missing
        print("Missing Cloudflare API credentials.")
        return

    # Cloudflare API端点
    # Cloudflare API endpoint
    url = "https://api.cloudflare.com/client/v4/accounts/{}/firewall/access_rules/rules".format(account_id)

    # 创建请求负载
    # Create the request payload
    data = {
        "mode": "block",
        "configuration": {
            "target": "asn",
            "value": asn  # 仅限数字部分
        },
        "notes": "Datacenter ASN"
    }

    # 设置请求头
    # Set the request headers
    headers = {
        "X-Auth-Email": email,
        "X-Auth-Key": api_key,
        "Content-Type": "application/json"
    }

    # 发送POST请求以阻止ASN
    # Make the POST request to block the ASN
    response = requests.post(url, json=data, headers=headers)

    # 处理Cloudflare API的响应
    # Handle response from Cloudflare API
    if response.status_code == 200:
        print("Successfully blocked ASN {} in Cloudflare.".format(asn))
    else:
        print("Failed to block ASN {}. Response: {}".format(asn, response.text))

def main():
    # 验证命令行参数
    # Validate command line arguments
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("\nUsage:\n")
        print("proxycheck <IP_address>    --    Checks IP and caches details")
        print("proxycheck <IP_address> [-u]    --    Force checks IP from ProxyCheck and updates cache")
        print("proxycheck -e <email_address>    --    Checks email address\n")
        sys.exit(1)

    option = sys.argv[1]
    # 从用户的主目录加载环境变量
    # Load environment variables from the user's home directory
    env_vars = load_env_variables("~/env.gipc")

    # 使用proxycheck.io获取IP或电子邮件信息
    # Fetch IP or email information using proxycheck.io
    api_key = env_vars.get("PROXYCHECK_API_KEY")
    if not api_key:
        # 如果缺少proxycheck API密钥，则出错
        # Error if proxycheck API key is missing
        print("Error: PROXYCHECK_API_KEY is missing in the environment file.")
        sys.exit(1)

    if option == '-e':
        # 处理电子邮件地址检查
        # Handle email address check
        if len(sys.argv) != 3:
            print("Usage: proxycheck -e <email_address>")
            sys.exit(1)
        email = sys.argv[2]
        fetch_email_info(email, api_key)
    else:
        # 处理IP地址检查
        # Handle IP address check
        ip = option
        force_update = '-u' in sys.argv
        ip_info, source = fetch_ip_info_with_operator(ip, api_key, force_update)
        parse_ip_info(ip, ip_info, env_vars)

if __name__ == "__main__":
    main()
