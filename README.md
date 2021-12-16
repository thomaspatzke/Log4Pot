# Log4Pot

A honeypot for the Log4Shell vulnerability (CVE-2021-44228).

## Features

* Listen on various ports for Log4Shell exploitation.
* Detect exploitation in request line and headers.
* Log to file and Azure blob storage.

## Usage

1. Install Poetry: `curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3 -`
2. Fetch this GitHub repository `git clone https://github.com/thomaspatzke/Log4Pot.git`
3. Change directory into the local copy with `cd Log4Pot`
4. Install dependencies: `poetry install`
5. Put parameters into log4pot.conf.
6. Run: `poetry run python log4pot.py @log4pot.conf`

Alternatively, you can also run log4pot without external dependencies:
```
$ python log4pot.py @log4pot.conf
```
This will run log4pot without support for logging to Azure blob storage.

## Analyzing Logs with JQ

List payloads from exploitation attempts:
```
select(.type == "exploit") | .payload
```

Decode all base64-encoded payloads from JNDI exploit:
```
select(.type == "exploit" and (.payload | contains("Base64"))) | .payload | sub(".*/Base64/"; "") | sub ("}$"; "") | @base64d
```
