from ast import Call
from dataclasses import dataclass
from datetime import datetime
import json
from typing import Callable, Dict, Iterable, List
import pandas as pd
from log4pot.expression_parser import parse as parse_payload
from log4pot.deobfuscator import deobfuscate as deobfuscate_payload

@dataclass
class LogParsingError(Exception):
    logfile : str
    logline : int
    error_type : str
    exception : Exception

    def __str__(self):
        return (f"Log4Pot log parse error type {self.error_type} in log file '{self.logfile}' line {logline}: {str(self.exception)}")

@dataclass
class LogAnalyzer:
    logs : List[List[str]]
    keep_deobfuscation : bool = False
    old_deobfuscator : bool = False

    def __post_init__(self):
        if self.old_deobfuscator:
            deobfuscator = parse_payload
        else:
            deobfuscator = deobfuscate_payload
        self.load_logs(deobfuscator)

    def load_logs(self, deobfuscator : Callable[[str], str]):
        """
        Parse logs specified while initialization into events element. Additionally:

        * Converts timestamps into datetime objects.
        * Sorts log events by timestamp.
        * Deobfuscate payload in cases where this wasn't done (logs from older Log4Pot versions)

        This is invoked at initialization and usually must not be called again.
        """
        parsed_events = list()
        lognum = 0
        for log in self.logs:
            lognum += 1
            linenum = 1
            for line in log:
                try:
                    parsed_event : dict = json.loads(line)
                except Exception as e:
                    raise LogParsingError(lognum, linenum, "JSON parsing", e)

                try:
                    parsed_event["timestamp"] = datetime.fromisoformat(parsed_event["timestamp"])
                except KeyError as e:
                    raise LogParsingError(lognum, linenum, "Timestamp missing", e)

                if "payload" in parsed_event and ("deobfuscated_payload" not in parsed_event or not self.keep_deobfuscation):
                    parsed_event["deobfuscated_payload"] = deobfuscator(parsed_event["payload"])

                parsed_events.append(parsed_event)

        self.events = sorted(
            parsed_events,
            key=lambda e: e["timestamp"]
            )

    def event_count(self) -> int:
        """Return event count."""
        return len(self.events)

    def filter_event_type(self, event_type : str) -> Iterable[Dict]:
        return filter(
            lambda e: e["type"] == event_type,
            self.events
        )

    def df_exploits(self) -> pd.DataFrame:
        return pd.DataFrame(
            self.filter_event_type("exploit"),
            columns=["timestamp", "payload", "deobfuscated_payload"],
            )

    def df_payloads(self) -> pd.DataFrame:
        return pd.DataFrame(
            (
                {
                    **event,
                    "url": event.get("urls", dict()).keys(),
                    "sha256": event.get("urls", dict()).values(),
                }
                for event in self.filter_event_type("payload")
            ),
            columns=["timestamp", "javaCodeBase", "javaSerializedData", "url", "sha256"],
        ).explode(["url", "sha256"])

    def exploit_summary(self):
        df = self.df_exploits()
        return df.groupby("payload").agg(
            first_seen=pd.NamedAgg(column="timestamp", aggfunc="min"),
            last_seen=pd.NamedAgg(column="timestamp", aggfunc="max"),
        ).sort_values(by="first_seen")

    def deobfuscated_exploit_summary(self):
        df = self.df_exploits()
        return df.groupby("deobfuscated_payload").agg(
            first_seen=pd.NamedAgg(column="timestamp", aggfunc="min"),
            last_seen=pd.NamedAgg(column="timestamp", aggfunc="max"),
        ).sort_values(by="first_seen")

    def deobfuscation_summary(self):
        df = self.df_exploits()
        return df.groupby([ "deobfuscated_payload", "payload" ]).agg(
            first_seen=pd.NamedAgg(column="timestamp", aggfunc="min"),
            last_seen=pd.NamedAgg(column="timestamp", aggfunc="max"),
        ).sort_values(by="first_seen")

    def payload_url_summary(self, allowlist = [], denylist = []):
        df = self.df_payloads()
        df["url"] = df[["javaCodeBase", "url"]].values.tolist()
        df = df[["timestamp", "url"]].explode("url")
        df = df[~df["url"].isnull()]
        df["url"] = df["url"].apply(lambda url: url if "://" in url else "http://" + url)
        for pattern in allowlist:
            df = df[df["url"].str.match(pattern, False)]
        for pattern in denylist:
            df = df[~df["url"].str.match(pattern, False)]

        return df.groupby("url").agg(
            first_seen=pd.NamedAgg(column="timestamp", aggfunc="min"),
            last_seen=pd.NamedAgg(column="timestamp", aggfunc="max"),
        ).sort_values(by="first_seen")