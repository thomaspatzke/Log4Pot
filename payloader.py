import base64
import io
import os
import re
import shutil
from tempfile import TemporaryFile
from pathlib import Path
from typing import Union, Optional, Dict, BinaryIO
from urllib.parse import urlparse
from hashlib import sha256
from dataclasses import dataclass

try:
    import pycurl

    pycurl_available = True
except ImportError as e:
    print(
        f"Pycurl not available or there is an issue with curl dependencies: {e}"
    )
    pycurl_available = False

@dataclass
class Payloader:
    """Download and analyze exploit payloads."""
    download_dir: Optional[str] = None,
    upload_container: Optional["azure.storage.blob.ContainerClient"] = None,
    download_timeout: int = 10

    def process_payloads(self, parsed_jndi_string: str):
        if not pycurl_available:
            raise ImportError("Was not able to import pycurl correctly.")

        url = self.extract_url(parsed_jndi_string)
        url = urlparse(url)
        data = dict()
        with TemporaryFile() as f:
            if url.scheme == "ldap":            # ldap://
                data["jndi_handler"] = "ldap"
                self.curl(url.geturl(), f)
                data = self.process_ldap_response(f)
                ldap_destination_name = data["ldap_sha256"]
                self.store_file(f, ldap_destination_name)
                self.load_ldap_class(data)
            else:                               # everything else: pass to curl and hope it's able to handle it.
                data["jndi_handler"] = "generic"
                self.curl(url.geturl(), f)
                f.seek(0)
                h = sha256(f.read()).hexdigest()
                data["generic_sha256"] = h
                self.store_file(f, h)

        return data


    def process_ldap_response(self, f : BinaryIO) -> Dict:
        content = {}
        f.seek(0)
        data = f.read()
        h = sha256(data).hexdigest()
        data = str(data, "utf-8").split()
        for idx, value in enumerate(data):
            if ":" in value and "http:" not in value:
                content.update({value.strip(":"): data[idx + 1]})
        content["ldap_sha256"] = h
        return content


    def load_ldap_class(self, data : Dict):
        with TemporaryFile() as f:
            if "javaCodeBase" in data and "javaFactory" in data:
                # Download referenced external javaCodeBase
                data["class_type"] = "url_reference"
                url = data["javaCodeBase"] + data["javaFactory"] + ".class"
                self.curl(url, f)
                f.seek(0)
                class_content = f.read()
            elif data.get("javaClassName", "") == "java.lang.String" and \
                    data.get("javaSerializedData", None):
                # Base64 decode class serialized in javaSerializedData
                class_content = data.get("javaSerializedData", "")
                if re.match(r"[a-zA-Z0-9+/]={0,3}", class_content):
                    data["class_type"] = "serialized"
                    class_content = base64.b64decode(class_content.encode("ascii"))
                    f.write(class_content)
                else:
                    data["class_type"] = "serialized_invalid"
                    return
            else:
                data["class_type"] = "unknwon"
                return
            h = sha256(class_content).hexdigest()
            data["class_sha256"] = h
            self.store_file(f, h)


    def extract_url(self, url: str):
        """Parse URL from jndi expression."""
        index = url.find("jndi:")
        url = url[index + 5:]
        if "${" in url:
            raise ValueError(
                "URL seems to include either further expressions - try the expression parser - or environment variables.")
        return url.strip("{}")


    def curl(self, url: str, f) -> Union[str, None]:
        """Downloads data from URL, creates and writes into a temporary file and return temporary file path."""
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, url)
        curl.setopt(pycurl.FOLLOWLOCATION, True)
        curl.setopt(pycurl.USERAGENT, "Java/17.0.1")
        curl.setopt(pycurl.WRITEDATA, f)
        curl.setopt(pycurl.TIMEOUT, self.download_timeout)
        curl.perform()
        status_code = curl.getinfo(pycurl.RESPONSE_CODE)
        curl.close()

        if status_code > 302:
            raise FileNotFoundError("Server returned HTTP404, deleted the temporary file.")


    def store_file(self, f : BinaryIO, dest_name : str):
        self.copy_to_download(f, dest_name)
        self.upload_file_to_azure_blob(f, dest_name)


    def copy_to_download(self, sf : BinaryIO, dest_name : str):
        if self.download_dir:
            dest_path = Path(self.download_dir) / dest_name
            if not dest_path.exists():
                with dest_path.open("wb") as df:
                    sf.seek(0)
                    shutil.copyfileobj(sf, df)


    def upload_file_to_azure_blob(self, f : BinaryIO, target_name : str):
        """Upload file to Azure blob storage with SHA256 as name. Check if it already exists before upload."""
        if self.upload_container is not None:
            f.seek(0)
            d = f.read()
            blob = self.upload_container.get_blob_client(target_name)
            if not blob.exists():
                blob.upload_blob(d, length=len(d))