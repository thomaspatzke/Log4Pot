from io import StringIO
from datetime import datetime
import atexit
import hashlib
import signal


class S3Log:
    """
        write logs to S3 buckets
    """

    def __init__(self, s3_client, threshold=100, bucket=None, key_prefix="logs"):
        """
            :param s3_client: aws boto3 s3 client
            :param threshold: number of log records to keep in memory, before sending them to S3
            :param bucket: name of S3 bucket to used
            :param key_prefix: prefix of key name used to store data in the given S3 bucket

        """

        self.log_counter=0
        self.log_entry_threshold=threshold
        self.buffer=StringIO()
        self.bucket=bucket
        self.key_prefix=key_prefix
        self.s3=s3_client

        atexit.register(self.write_logs_to_s3, flush=True)

        def handler(signum, frame):
            print(f"Signal handler called with signal {signum}, flushing logs to S3!")
            self.write_logs_to_s3(flush=True)

        # Set the signal handler
        signal.signal(signal.SIGUSR1, handler)


    def log(self, msg):
        """
            :param msg: message to log
            :type msg: str
        """

        self.buffer.write(msg + "\n")
        self.log_counter+=1

        self.write_logs_to_s3()

    def log_payload(self, data, filename):
        """
            log payloads to S3

            :param data: data to upload
        """

        self.s3.put_object(Body=data, Bucket=self.bucket, Key=filename)

    def write_logs_to_s3(self, flush=False):
        """
            write cached logs to S3

            logs are cached in-memory and sent to S3 in batches, since it's not
            possible to append data to files in a S3 bucket.
            see: https://stackoverflow.com/questions/41783903/append-data-to-an-s3-object

            :param flush: upload logs, even if threshold is not yet reached
        """

        if (self.log_counter > self.log_entry_threshold or flush) and len(self.buffer.getvalue()) > 0:

            now=datetime.now()
            key= self.key_prefix+"_"+now.strftime("%Y-%m-%d_%H:%M:%S")+".json"
            self.s3.put_object(Body=self.buffer.getvalue(), Bucket=self.bucket, Key=key)
            self.log_counter=0
            self.buffer=StringIO()