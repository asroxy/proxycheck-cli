/*
Proxycheck-CLI

Author: Roxana Schram
Copyright (c) 2024 Roxana Schram
All rights reserved.

Description:
    This program fetches information for a given IP address using the proxycheck.io service.
    It also optionally allows the user to block the ASN associated with the IP in Cloudflare.
    The program is designed to work with an environment file ("env.gipc") from Global IPconnect's 
    Cloudflare DNS Manager to manage Cloudflare credentials. It is not required to have Global 
    IPconnect's Cloudflare DNS Manager, simply need to create as shown below.

Usage:
    proxycheck <IP_address>
    proxycheck <IP_address> -u
    proxycheck -e <email_address>

Requirements:
    - Go 1.16 or later
    - An environment file at ~/env.gipc containing Cloudflare credentials:
        CLOUDFLARE_API_KEY=<your_api_key>
        CLOUDFLARE_EMAIL=<your_email>
        CLOUDFLARE_ACCOUNT_ID=<your_account_id>
        PROXYCHECK_API_KEY=<proxycheck_api_key>

This program interacts with third-party services as part of its functionality:

- **Cloudflare API**: Used for managing firewall rules.
- **Proxycheck.io API**: Used for retrieving IP information.

These services are used under their respective terms of service. It is the user's responsibility to comply
with the terms of service for any third-party services utilized by this script.

Third-party Libraries Used:
    - Standard Go libraries (net/http, encoding/json, etc.)

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
   Roxana Schram, clearly stated in the modified version.

2. If someone modifies code from a modified version created by another person, they must also give credit to 
   all previous authors, including the original author, Roxana Schram. This chain of attribution must 
   remain intact regardless of how many modifications or derivative versions are made.

3. The above copyright notice and this permission notice shall be included in all copies or substantial 
   portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT 
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN 
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Environment variables structure to hold API keys and account details
// 环境变量结构体，用于存储 API 密钥和账户详情
type EnvVars struct {
	CloudflareAPIKey   string
	CloudflareEmail    string
	CloudflareAccountID string
	ProxycheckAPIKey   string
}

// Cache entry structure to hold cached IP or email information
// 缓存项结构体，用于存储缓存的 IP 或邮件信息
type CacheEntry struct {
	Timestamp int64                  `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// Load environment variables from a file based on the OS platform
// 从文件中加载环境变量，根据操作系统平台选择文件路径
func loadEnvVariables() (EnvVars, error) {
	var envFilePath string
	if runtime.GOOS == "windows" {
		envFilePath = filepath.Join(os.Getenv("HOMEPATH"), "env.gipc")
	} else {
		envFilePath = filepath.Join(os.Getenv("HOME"), "env.gipc")
	}

	file, err := os.Open(envFilePath)
	if err != nil {
		return EnvVars{}, fmt.Errorf("warning: environment file '%s' not found", envFilePath)
	}
	defer file.Close()

	// Read the environment file line by line and extract variables
	// 线过线读取环境文件，并提取变量
	scanner := bufio.NewScanner(file)
	vars := make(map[string]string)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			vars[parts[0]] = parts[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return EnvVars{}, fmt.Errorf("error reading environment file: %v", err)
	}

	// Return the environment variables extracted from the file
	// 返回从文件中提取的环境变量
	return EnvVars{
		CloudflareAPIKey:   vars["CLOUDFLARE_API_KEY"],
		CloudflareEmail:    vars["CLOUDFLARE_EMAIL"],
		CloudflareAccountID: vars["CLOUDFLARE_ACCOUNT_ID"],
		ProxycheckAPIKey:   vars["PROXYCHECK_API_KEY"],
	}, nil
}

// Load cached data from file if available
// 如果可用，从文件中加载缓存数据
func loadCache() (map[string]CacheEntry, error) {
	cacheFilePath := filepath.Join(os.Getenv("HOME"), "proxycheck_cache.json")
	file, err := os.Open(cacheFilePath)
	if err != nil {
		return make(map[string]CacheEntry), nil // No cache file found, return an empty map
	}
	defer file.Close()

	var cache map[string]CacheEntry
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&cache); err != nil {
		return nil, fmt.Errorf("error reading cache file: %v", err)
	}

	// Return the cache data
	// 返回缓存数据
	return cache, nil
}

// Save cache data to file
// 将缓存数据保存到文件
func saveCache(cache map[string]CacheEntry) error {
	cacheFilePath := filepath.Join(os.Getenv("HOME"), "proxycheck_cache.json")
	file, err := os.Create(cacheFilePath)
	if err != nil {
		return fmt.Errorf("error creating cache file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(cache); err != nil {
		return fmt.Errorf("error writing to cache file: %v", err)
	}

	// Successfully saved cache
	// 成功保存缓存
	return nil
}

// Fetch IP information using Proxycheck.io and update cache if necessary
// 使用 Proxycheck.io 获取 IP 信息，并在必要时更新缓存
func fetchIPInfo(ip, apiKey string, forceUpdate bool) (map[string]interface{}, string, error) {
	cache, err := loadCache()
	if err != nil {
		return nil, "", err
	}

	currentTime := time.Now().Unix()
	if entry, found := cache[ip]; found && !forceUpdate {
		if currentTime-entry.Timestamp < 7*24*60*60 { // 7 days in seconds
			return entry.Data, "cache", nil
		}
	}

	// Request IP information from Proxycheck.io
	// 从 Proxycheck.io 请求 IP 信息
	url := fmt.Sprintf("https://proxycheck.io/v2/%s?key=%s&tag=ProxyCheck_CLI&vpn=1&asn=1&node=1&risk=1&port=1", ip, apiKey)
	resp, err := http.Get(url)
	if err != nil {
		return nil, "", fmt.Errorf("error fetching data from Proxycheck.io: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", errors.New("failed to fetch IP info")
	}

	var ipInfo map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&ipInfo); err != nil {
		return nil, "", fmt.Errorf("error decoding response: %v", err)
	}

	// Update cache with new data
	// 使用新数据更新缓存
	if cache == nil {
		cache = make(map[string]CacheEntry)
	}
	cache[ip] = CacheEntry{
		Timestamp: currentTime,
		Data:      ipInfo,
	}
	saveCache(cache)

	return ipInfo, "proxycheck", nil
}

// Fetch email information using Proxycheck.io
// 使用 Proxycheck.io 获取邮件信息
func fetchEmailInfo(email, apiKey string) (map[string]interface{}, string, error) {
	url := fmt.Sprintf("https://proxycheck.io/v2/%s?key=%s&tag=ProxyCheck_CLI&email=1", email, apiKey)
	resp, err := http.Get(url)
	if err != nil {
		return nil, "", fmt.Errorf("error fetching data from Proxycheck.io: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", errors.New("failed to fetch email info")
	}

	var emailInfo map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&emailInfo); err != nil {
		return nil, "", fmt.Errorf("error decoding response: %v", err)
	}

	// Return email information
	// 返回邮件信息
	return emailInfo, "proxycheck", nil
}

// Parse and display IP information to the user
// 解析并向用户显示 IP 信息
func parseIPInfo(ip string, ipInfo map[string]interface{}) {
	fmt.Printf("\nIP Details: %s\n", ip)

	fields := map[string]string{
		"ASN":           "asn",
		"Provider":      "provider",
		"Organisation":  "organisation",
		"Continent":     "continent",
		"Country":       "country",
		"Region":        "region",
		"City":          "city",
		"Postal Code":   "postcode",
		"Latitude":      "latitude",
		"Longitude":     "longitude",
		"Proxy":         "proxy",
		"Type":          "type",
	}

	// Iterate over fields and display each one if available
	// 迭代某些字段，如果可用，则显示
	for label, key := range fields {
		value, ok := ipInfo[ip].(map[string]interface{})[key]
		if !ok {
			value = "N/A"
		}
		fmt.Printf("%s: %v\n", label, value)
	}

	// Extract operator and policies if available
	// 如果可用，提取运营商和政策信息
	operator, operatorExists := ipInfo[ip].(map[string]interface{})["operator"].(map[string]interface{})
	if operatorExists {
		fmt.Println("\nOperator Details:")
		fmt.Printf("Name: %s\n", operator["name"])
		fmt.Printf("URL: %s\n", operator["url"])
		fmt.Printf("Anonymity: %s\n", operator["anonymity"])
		fmt.Printf("Popularity: %s\n", operator["popularity"])
		if protocols, ok := operator["protocols"].([]interface{}); ok {
			fmt.Printf("Protocols: %s\n", strings.Join(interfaceSliceToStringSlice(protocols), ", "))
		}

		policies, policiesExists := operator["policies"].(map[string]interface{})
		if policiesExists {
			fmt.Println("\nPolicies:")
			for key, value := range policies {
				fmt.Printf("%s: %v\n", strings.ReplaceAll(strings.Title(key), "_", " "), value)
			}
		}
	} else {
		fmt.Println("\nNo operator details found for this IP.")
	}
}

// Parse and display email information to the user
// 解析并向用户显示邮件信息
func parseEmailInfo(email string, emailInfo map[string]interface{}) {
	fmt.Printf("\nEmail Details: %s\n", email)

	fields := map[string]string{
		"Disposable": "disposable",
		"Risk Score": "risk_score",
	}

	// Iterate over fields and display each one if available
	// 迭代某些字段，如果可用，则显示
	for label, key := range fields {
		value, ok := emailInfo[email].(map[string]interface{})[key]
		if !ok {
			value = "N/A"
		}
		fmt.Printf("%s: %v\n", label, value)
	}
}

// Block ASN in Cloudflare using provided credentials
// 使用提供的 Cloudflare 凭据阻止 ASN
func blockASNInCloudflare(asn string, envVars EnvVars) {
	apiKey := envVars.CloudflareAPIKey
	email := envVars.CloudflareEmail
	accountID := envVars.CloudflareAccountID

	if apiKey == "" || email == "" || accountID == "" {
		fmt.Println("Missing Cloudflare API credentials.")
		return
	}

	// Create request to block ASN in Cloudflare
	// 创建请求以在 Cloudflare 中阻止 ASN
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/firewall/access_rules/rules", accountID)
	data := map[string]interface{}{
		"mode":          "block",
		"configuration": map[string]string{"target": "asn", "value": asn},
		"notes":         "Datacenter ASN",
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("Error encoding JSON data: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	req.Header.Set("X-Auth-Email", email)
	req.Header.Set("X-Auth-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	responseBody, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("Successfully blocked ASN %s in Cloudflare.\n", asn)
	} else {
		fmt.Printf("Failed to block ASN %s. Response: %s, Details: %s\n", asn, resp.Status, string(responseBody))
	}
}

// Convert a slice of interfaces to a slice of strings
// 将接口切片转换为字符串切片
func interfaceSliceToStringSlice(slice []interface{}) []string {
	stringSlice := make([]string, len(slice))
	for i, v := range slice {
		stringSlice[i] = fmt.Sprintf("%v", v)
	}
	return stringSlice
}

// Main function to run the proxycheck command-line tool
// 主函数，运行 proxycheck 命令行工具
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: proxycheck <IP_address> or proxycheck -e <email_address>")
		return
	}

	option := os.Args[1]
	envVars, err := loadEnvVariables()
	if err != nil {
		fmt.Println(err)
		return
	}

	if envVars.ProxycheckAPIKey == "" {
		fmt.Println("Error: PROXYCHECK_API_KEY is missing in the environment file.")
		return
	}

	if option == "-e" {
		if len(os.Args) != 3 {
			fmt.Println("Usage: proxycheck -e <email_address>")
			return
		}
		email := os.Args[2]
		emailInfo, source, err := fetchEmailInfo(email, envVars.ProxycheckAPIKey)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Results fetched from %s.\n", source)
		parseEmailInfo(email, emailInfo)
	} else {
		ip := option
		forceUpdate := len(os.Args) == 3 && os.Args[2] == "-u"
		ipInfo, source, err := fetchIPInfo(ip, envVars.ProxycheckAPIKey, forceUpdate)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("Results fetched from %s.\n", source)
		parseIPInfo(ip, ipInfo)

		// Only prompt the user to block ASN if Cloudflare credentials are available
		// 仅当 Cloudflare 凭据可用时提示用户阻止 ASN
		asn, asnExists := ipInfo[ip].(map[string]interface{})["asn"].(string)
		if asnExists && envVars.CloudflareAPIKey != "" {
			var response string
			fmt.Printf("\nDo you want to block ASN %s in Cloudflare? (y/n, default: n): ", asn)
			fmt.Scanln(&response)
			if strings.ToLower(response) == "y" {
				blockASNInCloudflare(asn, envVars)
			}
		}
	}
}
