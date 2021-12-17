import io
import os
import shutil
import tempfile
from pathlib import Path
from typing import Union, Optional, Dict

try:
    import pycurl

    pycurl_available = True
except ImportError as e:
    print(
        f"Pycurl not available or there is an issue with curl dependencies: {e}"
    )
    pycurl_available = False
from urllib3.util.url import parse_url


def process_payloads(
        parsed_jndi_string: str,
        uuid: str,
        download_dir: Optional[str] = None
):
    if not pycurl_available:
        raise ImportError("Was not able to import pycurl correctly.")

    url = extract_url(parsed_jndi_string)
    url = parse_url(url)
    if url.scheme not in [
        "https",
        "http",
        "ldap"
    ]:
        raise ValueError(f"Cannot process {url.scheme} URLs.")
    filepath = load_file(str(url))
    data = process_file(filepath)
    if download_dir:
        download_dir = Path(download_dir)
        new_path = download_dir.joinpath(uuid + ".dat")
        shutil.move(str(filepath), new_path)
        data.update({"filepath": str(new_path)})
    else:
        os.remove(str(filepath))
    return data


def extract_url(url: str):
    """Parse URL from jndi expression."""
    index = url.find("jndi:")
    url = url[index + 5:]
    if "${" in url:
        raise ValueError(
            "URL seems to include either further expressions - try the expression parser - or environment variables.")
    return url.strip("{}")


def load_file(url: str) -> Union[str, None]:
    """Downloads data from URL, creates and writes into a temporary file and return temporary file path."""
    fd, tmp = tempfile.mkstemp()
    status_code = 200
    with os.fdopen(fd, mode="wb") as handle:
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, url)
        curl.setopt(pycurl.FOLLOWLOCATION, True)
        curl.setopt(pycurl.USERAGENT, "Apache-Coyote/1.1")
        curl.setopt(pycurl.WRITEDATA, handle)
        curl.perform()
        status_code = curl.getinfo(pycurl.RESPONSE_CODE)
        curl.close()

    if status_code > 302:
        os.remove(tmp)
        raise FileNotFoundError("Server returned HTTP404, deleted the temporary file.")
    return tmp


def process_file(filepath: str) -> Dict:
    content = {}
    with io.open(filepath, encoding="utf-8") as handle:
        data = handle.read()
    data = data.split()
    for idx, value in enumerate(data):
        if ":" in data:
            content.update({value: data[idx + 1]})
    return content
