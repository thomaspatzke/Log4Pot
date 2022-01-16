# Generate summaries from Log4Pot logs

from argparse import ArgumentParser
import argparse
from pathlib import Path
from log4pot.loganalyzer import LogAnalyzer, LogParsingError
from sys import stderr, exit
import csv

default_csv_param = {
    "sep": ";",
    "quoting": csv.QUOTE_ALL,
}

argparser = ArgumentParser(description="Generate summaries from Log4Pot logs.")
argparser.add_argument("--output", "-o", type=Path, default=Path("."), help="Output directory for summaries.")
argparser.add_argument("--summaries", "-s", default="all", help="Summaries to generate (all, exploits, deobfuscates_exploits, deobfuscation, payload_urls) as comma-separated list")
argparser.add_argument("--keep-deobfuscation", "-k", action="store_true", help="Keep payload deobfuscation from logs instead of deobfuscate again.")
argparser.add_argument("--old-deobfuscator", "-O", action="store_true", help="Deobfuscate payloads with old deobfuscator.")
argparser.add_argument("--url-allowlist", "-ua", default="default-url-allowlist", type=argparse.FileType("r"), help="URL pattern allowlist to use for payload_url summary.")
argparser.add_argument("--url-denylist", "-ud", default="default-url-denylist", type=argparse.FileType("r"), help="URL pattern denylist to use for payload_url summary.")
argparser.add_argument("logfile", nargs="+", type=Path, help="Log4Pot log file or directory containing such files.")
args = argparser.parse_args()

summaries = frozenset(args.summaries.split(","))
url_allowlist = [
    line.strip()
    for line in args.url_allowlist.readlines()
]
args.url_allowlist.close()
url_denylist = [
    line.strip()
    for line in args.url_denylist.readlines()
]
args.url_denylist.close()

paths = list()
for logfile in args.logfile:
    if not logfile.exists():
        print(f"File '{str(logfile)}' not found!", file=stderr)
        exit(1)

    if logfile.is_dir():
        paths.extend(logfile.glob("**/*"))
    else:
        paths.append(logfile)

logs = [
    path.open("r").read()
    for path in paths
]

loganalyzer = LogAnalyzer(logs, args.keep_deobfuscation, args.old_deobfuscator)
print(f"Loaded {loganalyzer.event_count()} events")

if "all" in summaries or "exploits" in summaries:
    df_payload_summary = loganalyzer.exploit_summary()
    df_payload_summary.reset_index().to_csv(
        args.output / "epxloit_summary.csv",
        columns=("first_seen", "last_seen", "payload"),
        index=False,
        **default_csv_param,
        )
    print(f"Wrote {len(df_payload_summary)} raw exploits.")

if "all" in summaries or "deobfuscated_exploits" in summaries:
    df_deobfuscated_payload_summary = loganalyzer.deobfuscated_exploit_summary()
    df_deobfuscated_payload_summary.reset_index().to_csv(
        args.output / "deobfuscated_exploit_summary.csv",
        columns=("first_seen", "last_seen", "deobfuscated_payload"),
        index=False,
        **default_csv_param,
        )
    print(f"Wrote {len(df_deobfuscated_payload_summary)} deobfuscated exploits.")

if "all" in summaries or "deobfuscation" in summaries:
    df_deobfuscation_summary = loganalyzer.deobfuscation_summary()
    df_deobfuscation_summary.reset_index().to_csv(
        args.output / "deobfuscation_summary.csv",
        columns=("first_seen", "last_seen", "payload", "deobfuscated_payload"),
        index=False,
        **default_csv_param,
        )
    print(f"Wrote deobfuscation_summary with {len(df_deobfuscation_summary)} items.")

if "all" in summaries or "payload_urls" in summaries:
    df = loganalyzer.payload_url_summary(url_allowlist, url_denylist)
    df.reset_index().to_csv(
        args.output / "payload_urls.csv",
        columns=("first_seen", "last_seen", "url"),
        index=False,
        **default_csv_param,
        )
    print(f"Wrote {len(df)} payload URLs.")