import base64
import io
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Union, Optional, Dict
from urllib3.util.url import parse_url
from hashlib import sha256

try:
    import pycurl

    pycurl_available = True
except ImportError as e:
    print(
        f"Pycurl not available or there is an issue with curl dependencies: {e}"
    )
    pycurl_available = False

def process_payloads(
        parsed_jndi_string: str,
        uuid: str,
        download_dir: Optional[str] = None,
        upload_container: Optional["azure.storage.blob.ContainerClient"] = None,
        download_class: Optional[bool] = False,
        download_timeout: Optional[int] = 10
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
    filepath = load_file(str(url), download_timeout)
    data = process_file(filepath)
    data["jndi_sha256"] = upload_file(upload_container, filepath)

    if download_dir:
        download_dir = Path(download_dir)
        new_path = download_dir.joinpath(uuid + ".dat")
        shutil.move(str(filepath), new_path)
        data["filepath"] = str(new_path)

        new_path = download_dir.joinpath(uuid + ".class.dat")
        if download_class:
            if "javaCodeBase" in data and "javaFactory" in data:
                # Download referenced external javaCodeBase
                url = data["javaCodeBase"] + data["javaFactory"] + ".class"
                temp_path = load_file(url)
                shutil.move(temp_path, new_path)
                data["class_filepath"] = str(new_path)
                data["class_sha256"] = upload_file(upload_container, new_path)
            elif data.get("javaClassName", "") == "java.lang.String" and \
                    data.get("javaSerializedData", None):
                # Base64 decode class serialized in javaSerializedData
                jsd = data.get("javaSerializedData", "")
                if re.match(r"[a-zA-Z0-9+/]={0,3}", jsd):
                    jsd = base64.b64decode(jsd.encode("ascii"))
                    with io.open(new_path, "wb") as handle:
                        handle.write(jsd)
                    data["class_filepath"] = str(new_path)
                data["class_sha256"] = upload_file(upload_container, new_path)
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


def load_file(url: str, timeout: Optional[int] = 10) -> Union[str, None]:
    """Downloads data from URL, creates and writes into a temporary file and return temporary file path."""
    fd, tmp = tempfile.mkstemp()
    status_code = 200
    with os.fdopen(fd, mode="wb") as handle:
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, url)
        curl.setopt(pycurl.FOLLOWLOCATION, True)
        curl.setopt(pycurl.USERAGENT, "Java/17.0.1")
        curl.setopt(pycurl.WRITEDATA, handle)
        curl.setopt(pycurl.TIMEOUT, timeout)
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
        if ":" in value and "http:" not in value:
            content.update({value.strip(":"): data[idx + 1]})
    return content

def upload_file(container : Optional["azure.storage.blob.ContainerClient"], file_name : str) -> str:
    """Upload file to Azure blob storage with SHA256 as name. Check if it already exists before upload. Return SHA256 of file in any case."""
    if container is not None:
        f = open(file_name, "rb")
        d = f.read()
        f.close()
        h = sha256(d).hexdigest()
        blob = container.get_blob_client(h)
        if not blob.exists():
            blob.upload_blob(d, length=len(d))
        return h