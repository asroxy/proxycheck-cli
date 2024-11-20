#### Description:
This program fetches information for a given IP address or email using the proxycheck.io service. It also optionally allows the user to block the ASN associated with the IP in Cloudflare. The program is designed to work with an environment file ("env.gipc") from Global IPconnect's Cloudflare DNS Manager to manage Cloudflare credentials. You do not need to have the DNS manager from them, just create the env file as shown below.

**Installation of compiled releases**:

Once you have extracted the binary, browse to it's location using your preferred terminal or prompt and use the following commands to move the file allowing easy use of it.

— Windows
```
move proxycheck.exe C:\Windows\
```
— Linux
```
mv proxycheck /usr/local/bin
```
— Mac
```
xattr -dr com.apple.quarantine ./proxycheck
mv proxycheck /usr/local/bin
```        
Usage:

	proxycheck <IP_address>    --    Checks IP and caches details
	proxycheck <IP_address> [-u]    --    Force checks IP from ProxyCheck and updates cache
 	proxycheck -e <email_address>    --    Checks email address

**Requirements**:

—  Python 3.x

—  requests

—  An environment file at ~/env.gipc containing:
```
CLOUDFLARE_API_KEY=<your_api_key> (only needed for adding to WAF IP Access list)
CLOUDFLARE_EMAIL=<your_email> (only needed for adding to WAF IP Access list)
CLOUDFLARE_ACCOUNT_ID=<your_account_id> (only needed for adding to WAF IP 
PROXYCHECK_API_KEY=<proxycheck_api_key>
```

**Third-party Services**:

—  proxycheck.io API for retrieving IP information.

—  Cloudflare API for managing firewall rules.

**These services are used under their respective terms of service.**

**Third-party Libraries Used**:

—  requests: Licensed under the MIT License (https://github.com/psf/requests)

![proxycheck-cli(solaris)](https://github.com/user-attachments/assets/54717eb4-32ae-43ea-a85c-096cb3da87c8)
![proxycheck-cli(windows)](https://github.com/user-attachments/assets/26fcd69e-9b45-448e-a4c2-d68b887b4a42)
