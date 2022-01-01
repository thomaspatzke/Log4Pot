# Generate summaries from Log4Pot logs

from argparse import ArgumentParser
from pathlib import Path
from log4pot.loganalyzer import LogAnalyzer, LogParsingError
from sys import stderr, exit

argparser = ArgumentParser(description="Generate summaries from Log4Pot logs.")
argparser.add_argument("--output", "-o", type=Path, default=Path("."), help="Output directory for summaries.")
argparser.add_argument("--summaries", "-s", default="all", help="Summaries to generate (all, payloads, deobfuscates_payloads, deobfuscation) as comma-separated list")
argparser.add_argument("--keep-deobfuscation", "-k", action="store_true", help="Keep payload deobfuscation from logs instead of deobfuscate again.")
argparser.add_argument("--old-deobfuscator", "-O", action="store_true", help="Deobfuscate payloads with old deobfuscator.")
argparser.add_argument("logfile", nargs="+", type=Path, help="Log4Pot log file or directory containing such files.")
args = argparser.parse_args()

summaries = frozenset(args.summaries.split(","))

paths = list()
for logfile in args.logfile:
    if not logfile.exists():
        print(f"File '{str(logfile)}' not found!", file=stderr)
        exit(1)

    if logfile.is_dir():
        paths.extend(logfile.glob("**/*"))
    else:
        paths.append(logfile)

logs = LogAnalyzer(paths)
print(f"Loaded {logs.event_count()} events")

if "all" in summaries or "payloads" in summaries:
    df_payload_summary = logs.payload_summary()
    df_payload_summary.reset_index().to_csv(
        args.output / "payload_summary.csv",
        columns=("first_seen", "last_seen", "payload"),
        index=False,
        )
    print(f"Wrote {len(df_payload_summary)} raw payloads.")

if "all" in summaries or "deobfuscated_payloads" in summaries:
    df_deobfuscated_payload_summary = logs.deobfuscated_payload_summary()
    df_deobfuscated_payload_summary.reset_index().to_csv(
        args.output / "deobfuscated_payload_summary.csv",
        columns=("first_seen", "last_seen", "deobfuscated_payload"),
        index=False,
        )
    print(f"Wrote {len(df_deobfuscated_payload_summary)} deobfuscated payloads.")

if "all" in summaries or "deobfuscation" in summaries:
    df_deobfuscation_summary = logs.deobfuscation_summary()
    df_deobfuscation_summary.reset_index().to_csv(
        args.output / "deobfuscation_summary.csv",
        columns=("first_seen", "last_seen", "payload", "deobfuscated_payload"),
        index=False,
        )
    print(f"Wrote {len(df_deobfuscation_summary)} deobfuscated payloads.")