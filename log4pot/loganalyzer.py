from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Dict, Iterable, List
import pandas as pd
from log4pot.expression_parser import parse as parse_payload

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
    logfiles : List[Path]

    def __post_init__(self):
        self.logfiles = [
            Path(logfile)
            for logfile in self.logfiles
        ]
        self.load_logs()

    def load_logs(self):
        """
        Load log files specified while initialization into events element. Additionally:

        * Converts timestamps into datetime objects.
        * Sorts log events by timestamp.
        * Adds source file name to each log event.
        * Deobfuscate payload in cases where this wasn't done (logs from older Log4Pot versions)

        This is invoked at initialization and usually must not be called again.
        """
        parsed_events = list()
        for logfile in self.logfiles:
            f = logfile.open("r")
            logname = logfile.name
            i = 1
            for event in f.readlines():
                try:
                    parsed_event : dict = json.loads(event)
                except Exception as e:
                    raise LogParsingError(logname, i, "JSON parsing", e)

                try:
                    parsed_event["timestamp"] = datetime.fromisoformat(parsed_event["timestamp"])
                except KeyError as e:
                    raise LogParsingError(logname, i, "Timestamp missing", e)

                if "payload" in parsed_event and "deobfuscated_payload" not in parsed_event:
                    parsed_event["deobfuscated_payload"] = parse_payload(parsed_event["payload"])

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

    def df_payloads(self) -> pd.DataFrame:
        return pd.DataFrame(
            self.filter_event_type("exploit"),
            columns=["timestamp", "payload", "deobfuscated_payload"],
            )

    def payload_summary(self):
        df = self.df_payloads()
        return df.groupby("payload").agg(
            first_seen=pd.NamedAgg(column="timestamp", aggfunc="min"),
            last_seen=pd.NamedAgg(column="timestamp", aggfunc="max"),
        ).sort_values(by="first_seen")

    def deobfuscated_payload_summary(self):
        df = self.df_payloads()
        return df.groupby("deobfuscated_payload").agg(
            first_seen=pd.NamedAgg(column="timestamp", aggfunc="min"),
            last_seen=pd.NamedAgg(column="timestamp", aggfunc="max"),
        ).sort_values(by="first_seen")

    def deobfuscation_summary(self):
        df = self.df_payloads()
        return df.groupby([ "payload", "deobfuscated_payload" ]).agg(
            first_seen=pd.NamedAgg(column="timestamp", aggfunc="min"),
            last_seen=pd.NamedAgg(column="timestamp", aggfunc="max"),
        ).sort_values(by="first_seen")