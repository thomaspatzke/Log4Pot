# Log4Pot

A honeypot for the Log4Shell vulnerability (CVE-2021-44228).

License: [GPLv3.0](https://www.gnu.org/licenses/gpl-3.0.html)

## Features

* Listen on various ports for Log4Shell exploitation.
* Detect exploitation in request line and headers.
* Log to file and Azure blob storage.

## Usage

1. Install Poetry: `curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3 -`
2. Fetch this GitHub repository `git clone https://github.com/thomaspatzke/Log4Pot.git`
3. Change directory into the local copy with `cd Log4Pot`
4. Install pycurl dependencies (Debian / Ubuntu): `apt install libcurl4-openssl-dev libssl-dev python3-dev build-essential`
5. Install python dependencies: `poetry install`
6. Put parameters into log4pot.conf

	```
	--port: Configure listening port
	--log: Configure log file to use
	--blob-connection-string: Azure blob storage connection string
	--log-container: Azure blob container for logs
	--log-blob: Azure blob for logs
	--server-header: Replace the default server header
	--download-payloads: Download http(s) and ldap payloads and log indicators
	--download-class: Implement downloading Java Class file referenced by the payload
	--download-dir: Set a download directory. If given, payloads are stored persistently and are not deleted after analysis
	```
7. Run: `poetry run python log4pot.py @log4pot.conf`

Alternatively, you can also run log4pot without external dependencies:
```
$ python log4pot.py @log4pot.conf
```
This will run log4pot without support for logging to Azure blob storage.

## Redirecting traffic / non-container setup

To redirect traffic to port 80 and 443 to Log4Pot, use following iptables commands:

`iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080`

`iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8443`

## Analyzing Logs with JQ

List payloads from exploitation attempts:
```
select(.type == "exploit") | .payload
```

Decode all base64-encoded payloads from JNDI exploit:
```
select(.type == "exploit" and (.payload | contains("Base64"))) | .payload | sub(".*/Base64/"; "") | sub ("}$"; "") | @base64d
```
