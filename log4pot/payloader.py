import base64
import binascii
from multiprocessing.sharedctypes import Value
import re
import shutil
from tempfile import TemporaryFile
from pathlib import Path
from typing import Set, Union, Optional, Dict, BinaryIO
from urllib.parse import urlparse
from hashlib import sha256
from dataclasses import dataclass
import pycurl

re_urls = [     # Regular expressions for extraction of URLs from payloads and downloaded samples.
    re.compile(b'\w{3,5}://[^\x00-\x20;"\')\x7b-\xff]+'),                   # URLs prefixed with scheme and :// until first appearance of nonprintable or ending character.
    re.compile(b'(?<=\s)\w+(?:\.\w+){2,}/[^\x00-\x20;"\')\x7b-\xff]+'),     # HTTP URLs without scheme. Preceded by whitespace followed by IP/domain name with at least two dots and continuing until first nonprintable or ending character appears.
]
re_url_exclusion = re.compile("(?:github|google|gstatic|upx)")
re_base64_cmd = re.compile('Command/Base64/([a-zA-Z0-9+/]+={0,3})')
re_obfusc_charcode = re.compile(b"fromCharCode\(([\d,\s]+)\)")

@dataclass
class Payloader:
    """Download and analyze exploit payloads."""
    download_dir: Optional[str] = None,
    upload_container: Optional["azure.storage.blob.ContainerClient"] = None,
    download_timeout: int = 10
    s3log: Optional["log4pot.s3.S3Log"] = None

    def process_payloads(self, parsed_jndi_string: str):
        url = self.extract_url(parsed_jndi_string)
        url = urlparse(url)
        data = dict()
        with TemporaryFile() as f:
            if url.scheme.startswith("ldap"):            # ldap://
                data["jndi_handler"] = "ldap"
                try:
                    self.curl(url.geturl(), f)
                except Exception as e:
                    data["error"] = str(e)
                    return data
                data = self.process_ldap_response(f)
                ldap_destination_name = data["ldap_sha256"]
                self.store_file(f, ldap_destination_name)

                # extract or download exploit class
                class_content = self.load_ldap_class(data)
                if class_content is not None:
                    urls = self.extract_urls_from_payload(class_content)
                else:
                    urls = set()

                # extract command from base64 encoded DN part used in common JNDI exploits
                if (m := re_base64_cmd.search(data.get("DN", ""))):
                    try:
                        decoded = base64.b64decode(m.group(1))
                        urls.update(self.extract_urls_from_payload(decoded))
                    except binascii.Error:
                        pass

                data["urls"] = self.load_urls_recursively(urls)

            else:                               # everything else: pass to curl and hope it's able to handle it.
                data["jndi_handler"] = "generic"
                try:
                    self.curl(url.geturl(), f)
                except Exception as e:
                    data["error"] = str(e)
                    return data
                h = self.hash_file(f)
                data["generic_sha256"] = self.store_file(f)

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


    def load_ldap_class(self, data : Dict) -> Optional[bytes]:
        """Loads class referenced or contained serialized in LDAP object."""
        with TemporaryFile() as f:
            if "javaCodeBase" in data and "javaFactory" in data:
                # Download referenced external javaCodeBase
                data["class_type"] = "url_reference"
                url = data["javaCodeBase"] + data["javaFactory"] + ".class"
                try:
                    self.curl(url, f)
                except Exception as e:
                    data["error"] = str(e)
                    return
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
            data["class_sha256"] = self.store_file(f)
            return class_content

    def extract_url(self, url: str):
        """Parse URL from jndi expression."""
        index = url.find("jndi:")
        url = url[index + 5:]
        if "${" in url:
            raise ValueError(
                "URL seems to include either further expressions - try the expression parser - or environment variables.")
        return url.strip("{}")


    def extract_urls_from_payload(self, payload : bytes) -> Set[str]:
        """Extract all URLs from a (binary) payload."""
        payloads = [ payload ]
        try:
            if (m := re_obfusc_charcode.search(payload)):
                charcodes = str(m.group(1), encoding="iso-8859-1").replace(" ", "").split(",")
                deobfuscated = "".join((
                    chr(int(c))
                    for c in charcodes
                ))
                payloads.append(bytes(deobfuscated, encoding="utf-8"))
        except (ValueError, OverflowError):
            pass

        urls = {
                    str(url, "iso-8859-1")
                    for p in payloads
                    for re_url in re_urls
                    for url in re_url.findall(p)
                }
        return urls

    def load_urls_recursively(self, urls : Set[str], visited_urls : Set[str] = set(), visit_limit : int = 10) -> Dict[str, str]:
        """
        Download payloads from URLs and recursively visit contained URLs. Tracks visited URLs and sets upper limit for URL count.

        Return dict with URL mapped to the hash of the downloaded payload.
        """
        url_info = dict()
        content_urls = set()
        for url in urls:
            if url not in visited_urls:
                if re_url_exclusion.search(url):
                    url_info[url] = "excluded"
                else:
                    with TemporaryFile() as f:
                        try:
                            self.curl(url, f)
                            url_info[url] = self.store_file(f)
                        except Exception as e:
                            url_info[url] = "error: " + str(e)
                        visited_urls.add(url)
                        f.seek(0)
                        content = f.read()
                    content_urls.update(self.extract_urls_from_payload(content))
                    if len(visited_urls) >= visit_limit:
                        return url_info

        for url in content_urls:
            url_info.update(self.load_urls_recursively(content_urls, visited_urls))
            if len(visited_urls) >= visit_limit:
                return url_info

        return url_info


    def curl(self, url: str, f):
        """Downloads data from URL, creates and writes into a temporary file."""
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
            return False
        else:
            return True

    def hash_file(self, f : BinaryIO) -> str:
        """Calculate SHA256 on file descriptor and return it hex-encoded."""
        f.seek(0)
        return sha256(f.read()).hexdigest()

    def store_file(self, f : BinaryIO, dest_name : Optional[str] = None) -> str:
        """Store file in file system and Azure blob storage and return target name, which is specified or calculated (SHA256 of content)."""
        if dest_name is None:
            dest_name = self.hash_file(f)
        try:
            self.copy_to_download(f, dest_name)
        except FileNotFoundError:
            pass
        self.upload_file_to_azure_blob(f, dest_name)
        self.upload_file_to_s3(f, dest_name)
        return dest_name


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

    def upload_file_to_s3(self, f: BinaryIO, target_name: str):
        """ upload file to S3 bucket """
        if self.s3log is not None:
            f.seek(0)
            d = f.read()
            self.s3log.log_payload(d, target_name)