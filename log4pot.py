# A honeypot for the Log4Shell vulnerability (CVE-2021-44228)

from dataclasses import dataclass
from argparse import ArgumentParser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import json
from datetime import datetime
import socket
from typing import Any, List, Optional
from uuid import uuid4
import re
from azure.storage.blob import BlobServiceClient
from threading import Thread

re_exploit = re.compile("\${.*}")

@dataclass
class Logger:
    logfile : str
    blob_connection_str : Optional[str]
    log_container : Optional[str]
    log_blob : Optional[str]

    def __post_init__(self):
        self.f = open(self.logfile, "a")
        if self.blob_connection_str is not None:
            service_client = BlobServiceClient.from_connection_string(self.blob_connection_str)
            container = service_client.get_container_client(self.log_container)
            blob = container.get_blob_client(self.log_blob)
            blob.exists() or blob.create_append_blob()
            self.blob = blob
        else:
            self.blob = None

    def log(self, logtype : str, message : str, **kwargs):
        d = {
            "type": logtype,
            "timestamp": datetime.utcnow().isoformat(),
            **kwargs,
        }
        j = json.dumps(d) + "\n"
        self.f.write(j)
        self.blob.append_block(j)

    def log_start(self):
        self.log("start", "Log4Pot started")

    def log_request(self, server_port, client, port, request, headers, uuid):
        self.log("request", "A request was received", correlation_id=str(uuid), server_port=server_port, client=client, port=port, request=request, headers=dict(headers))

    def log_exploit(self, location, payload, uuid):
        self.log("exploit", "Exploit detected", correlation_id=str(uuid), location=location, payload=payload)

    def log_exception(self, e : Exception):
        self.log("exception", "Exception occurred", exception=str(e))

    def log_end(self):
        self.log("end", "Log4Pot stopped")

    def close(self):
        self.log_end()
        self.f.close()

class Log4PotHTTPRequestHandler(BaseHTTPRequestHandler):
    def do(self):
        self.uuid = uuid4()
        self.send_response(200)
        self.send_header("Content-Type", "text/json")
        self.end_headers()
        self.wfile.write(bytes(f'{{ "status": "ok", "id": "{self.uuid}" }}', "utf-8"))

        self.logger = self.server.logger
        self.logger.log_request(self.server.server_address[1], *self.client_address, self.requestline, self.headers, self.uuid)
        self.find_exploit("request", self.requestline)
        for header, value in self.headers.items():
            self.find_exploit(f"header-{header}", value)

    def find_exploit(self, location : str, content : str) -> bool:
        if (m := re_exploit.search(content)):
            logger.log_exploit(location, m.group(0), self.uuid)

    def __getattribute__(self, __name: str) -> Any:
        if __name.startswith("do_"):
            return self.do
        else:
            return super().__getattribute__(__name)

class Log4PotHTTPServer(ThreadingHTTPServer):
    def __init__(self, logger : Logger, *args, **kwargs):
        self.logger = logger
        super().__init__(*args, **kwargs)

class Log4PotServerThread(Thread):
    def __init__(self, logger : Logger, port : int, *args, **kwargs):
        self.port = port
        self.server = Log4PotHTTPServer(logger, ("", port), Log4PotHTTPRequestHandler)
        super().__init__(name=f"httpserver-{port}", *args, **kwargs)

    def run(self):
        try:
            self.server.serve_forever()
            self.server.server_close()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.log_exception(e)

class Log4PotArgumentParser(ArgumentParser):
    def convert_arg_line_to_args(self, arg_line: str) -> List[str]:
        return arg_line.split()

argparser = Log4PotArgumentParser(
    description="A honeypot for the Log4Shell vulnerability (CVE-2021-44228).",
    fromfile_prefix_chars="@",
    )
argparser.add_argument("--port", "-p", nargs="*", type=int, default=[8000, 8008, 8080, 8081, 8983, 9200], help="Listening port")
argparser.add_argument("--log", "-l", type=str, default="log4pot.log", help="Log file")
argparser.add_argument("--blob-connection-string", "-b", help="Azure blob storage connection string.")
argparser.add_argument("--log-container", "-lc", default="logs", help="Azure blob container for logs.")
argparser.add_argument("--log-blob", "-lb", default=socket.gethostname() + ".log", help="Azure blob for logs.")

args = argparser.parse_args()

logger = Logger(args.log, args.blob_connection_string, args.log_container, args.log_blob)
threads  = [
    Log4PotServerThread(logger, port)
    for port in args.port
]
logger.log_start()

for thread in threads:
    thread.start()
    print(f"Started Log4Pot server on port {thread.port}.")

for thread in threads:
    thread.join()
    print(f"Stopped Log4Pot server on port {thread.port}.")

logger.close()