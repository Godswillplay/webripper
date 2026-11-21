"""
Continuous Monitoring & Watch Mode Engine for WebRipper Recon 5.0.

Provides:
  - Authorised target configuration parsing & schedule interval parsing.
  - Baseline tracking and continuous diff execution.
  - Automated generation of change-only briefing.md and briefing.json.
  - Clean headless API drivable via CLI (webripper watch) and programmatic runners.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
from urllib.parse import urlparse

from ..models import RipperSettings
from .diff import HistoricalDiffEngine, WatchDiffBriefing


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class UnauthorizedTargetError(ValueError):
    """Raised when monitoring an unauthorised target."""
    pass


# ---------------------------------------------------------------------------
# Interval Parsing
# ---------------------------------------------------------------------------

_INTERVAL_REGEX = re.compile(
    r"^(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)?$",
    re.IGNORECASE,
)


def parse_interval(val: Union[int, float, str]) -> float:
    """
    Parse an interval specification into seconds as float.
    Supports human-readable formats: '30s', '5m', '2h', '1d', or numeric seconds.
    """
    if isinstance(val, (int, float)):
        if val <= 0:
            raise ValueError(f"Interval must be positive, got {val}")
        return float(val)

    s = str(val).strip()
    match = _INTERVAL_REGEX.match(s)
    if not match:
        raise ValueError(f"Invalid interval string: '{val}'. Expected format like '30s', '5m', '1h', or '300'.")

    num = float(match.group(1))
    unit = (match.group(2) or "s").lower()

    if num <= 0:
        raise ValueError(f"Interval value must be positive, got '{val}'")

    if unit.startswith("s"):
        return num
    elif unit.startswith("m"):
        return num * 60.0
    elif unit.startswith("h"):
        return num * 3600.0
    elif unit.startswith("d"):
        return num * 86400.0
    return num


# ---------------------------------------------------------------------------
# Configuration Data Models
# ---------------------------------------------------------------------------

@dataclass
class TargetConfig:
    """Configuration for an authorised target in watch mode."""
    url: str
    interval_seconds: float = 300.0
    authorised: bool = True
    profile: str = "standard"
    headers: Dict[str, str] = field(default_factory=dict)
    cookie: str = ""
    token: str = ""
    active_scanners: List[str] = field(default_factory=list)
    output_dir: str = ""
    name: str = ""
    max_runs: Optional[int] = None

    def __post_init__(self) -> None:
        url_clean = self.url.strip()
        if url_clean and not url_clean.startswith(("http://", "https://")):
            self.url = f"https://{url_clean}"
        else:
            self.url = url_clean

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "interval_seconds": self.interval_seconds,
            "authorised": self.authorised,
            "profile": self.profile,
            "headers": self.headers,
            "cookie": self.cookie,
            "token": self.token,
            "active_scanners": self.active_scanners,
            "output_dir": self.output_dir,
            "name": self.name,
            "max_runs": self.max_runs,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], default_interval: float = 300.0) -> TargetConfig:
        raw_url = str(data.get("url") or data.get("target") or "").strip()
        interval_val = data.get("interval") or data.get("interval_seconds") or default_interval
        parsed_interval = parse_interval(interval_val)
        authorised = bool(data.get("authorised", data.get("authorized", True)))

        return cls(
            url=raw_url,
            interval_seconds=parsed_interval,
            authorised=authorised,
            profile=str(data.get("profile", "standard")),
            headers=dict(data.get("headers", {})),
            cookie=str(data.get("cookie", "")),
            token=str(data.get("token", "")),
            active_scanners=list(data.get("active_scanners", [])),
            output_dir=str(data.get("output_dir", "")),
            name=str(data.get("name", "")),
            max_runs=data.get("max_runs"),
        )


@dataclass
class WatchConfig:
    """Master configuration for WebRipper Watch Mode."""
    targets: List[TargetConfig] = field(default_factory=list)
    default_interval_seconds: float = 300.0
    output_dir: str = "webripper_watch_output"
    enforce_authorisation: bool = True
    alert_on_critical: bool = True
    exit_on_drift: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "targets": [t.to_dict() for t in self.targets],
            "default_interval_seconds": self.default_interval_seconds,
            "output_dir": self.output_dir,
            "enforce_authorisation": self.enforce_authorisation,
            "alert_on_critical": self.alert_on_critical,
            "exit_on_drift": self.exit_on_drift,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WatchConfig:
        default_int_val = data.get("default_interval") or data.get("default_interval_seconds") or 300.0
        default_interval = parse_interval(default_int_val)

        raw_targets = data.get("targets", [])
        targets: List[TargetConfig] = []
        for t in raw_targets:
            if isinstance(t, str):
                targets.append(TargetConfig(url=t, interval_seconds=default_interval, authorised=True))
            elif isinstance(t, dict):
                targets.append(TargetConfig.from_dict(t, default_interval=default_interval))

        return cls(
            targets=targets,
            default_interval_seconds=default_interval,
            output_dir=str(data.get("output_dir", "webripper_watch_output")),
            enforce_authorisation=bool(data.get("enforce_authorisation", data.get("enforce_authorization", True))),
            alert_on_critical=bool(data.get("alert_on_critical", True)),
            exit_on_drift=bool(data.get("exit_on_drift", True)),
        )


def parse_watch_config(config_source: Union[str, Path, Dict[str, Any]]) -> WatchConfig:
    """
    Parse a WatchConfig from a dictionary, JSON file path, or JSON string.
    """
    if isinstance(config_source, dict):
        return WatchConfig.from_dict(config_source)

    if isinstance(config_source, (str, Path)):
        p = Path(config_source)
        if p.is_file():
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            return WatchConfig.from_dict(data)

        # Try parsing as JSON string directly
        s = str(config_source).strip()
        if s.startswith("{"):
            data = json.loads(s)
            return WatchConfig.from_dict(data)

    raise ValueError(f"Unable to parse watch config from source: {config_source}")


# ---------------------------------------------------------------------------
# Continuous Monitoring Watch Engine
# ---------------------------------------------------------------------------

class WatchEngine:
    """
    Continuous Monitoring & Watch Engine for WebRipper Recon 5.0.

    Drives scheduled diff briefings, maintains baseline history,
    and produces change-only briefing.md and briefing.json reports.
    """

    def __init__(
        self,
        config: Optional[WatchConfig] = None,
        diff_engine: Optional[HistoricalDiffEngine] = None,
        output_dir: Optional[str] = None,
        enforce_authorisation: bool = True,
    ) -> None:
        self.config = config or WatchConfig(enforce_authorisation=enforce_authorisation)
        self.diff_engine = diff_engine or HistoricalDiffEngine()
        self.output_dir = output_dir or self.config.output_dir
        self.baselines: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def set_baseline(self, target: str, scan_data: Any) -> None:
        """Register or update the baseline scan for a given target."""
        clean_target = target.strip().rstrip("/")
        with self._lock:
            self.baselines[clean_target] = scan_data

    def get_baseline(self, target: str) -> Optional[Any]:
        """Retrieve the recorded baseline scan for a given target."""
        clean_target = target.strip().rstrip("/")
        with self._lock:
            return self.baselines.get(clean_target)

    def load_baseline_from_file(self, target: str, file_path: str) -> None:
        """Load a previous scan from a JSON file as the target baseline."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Baseline file not found: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.set_baseline(target, data)

    def run_diff(
        self,
        previous_scan: Any,
        current_scan: Any,
        target: str = "",
        output_dir: Optional[str] = None,
    ) -> WatchDiffBriefing:
        """
        Execute historical diffing between previous and current scans,
        optionally exporting briefing.md and briefing.json if output_dir is supplied.
        """
        briefing = self.diff_engine.compare(
            previous_scan=previous_scan,
            current_scan=current_scan,
            target=target,
        )

        out = output_dir or self.output_dir
        if out:
            self.diff_engine.export_briefings(briefing, out)

        return briefing

    def evaluate(
        self,
        previous_scan: Any,
        current_scan: Any,
        target: str = "",
    ) -> WatchDiffBriefing:
        """Evaluate two scans and return the change-only briefing without file export."""
        return self.diff_engine.compare(
            previous_scan=previous_scan,
            current_scan=current_scan,
            target=target,
        )

    def execute_cycle(
        self,
        target_cfg: Union[TargetConfig, str],
        scan_fn: Optional[Callable[[TargetConfig], Any]] = None,
        output_dir: Optional[str] = None,
    ) -> WatchDiffBriefing:
        """
        Execute a single watch cycle for an authorised target:
          1. Validates target authorization.
          2. Obtains current scan via scan_fn.
          3. Diff against previously stored baseline.
          4. Exports change-only briefing.md and briefing.json.
          5. Updates baseline to current scan for subsequent cycles.
        """
        if isinstance(target_cfg, str):
            target_cfg = TargetConfig(url=target_cfg)

        # Authorization check
        if self.config.enforce_authorisation and not target_cfg.authorised:
            raise UnauthorizedTargetError(
                f"Target '{target_cfg.url}' is not authorised for continuous monitoring. "
                "Authorize target explicitly in TargetConfig(authorised=True)."
            )

        target_url = target_cfg.url
        baseline = self.get_baseline(target_url)

        # Execute scan
        if scan_fn is not None:
            current_scan = scan_fn(target_cfg)
        else:
            raise ValueError(
                f"No scan function provided to execute cycle for target '{target_url}'. "
                "Provide a scan_fn callable or use run_diff directly."
            )

        # Determine output directory
        target_out = output_dir or target_cfg.output_dir or self.output_dir
        if target_out:
            domain = urlparse(target_url).hostname or "target"
            target_out = os.path.join(target_out, domain)

        briefing = self.run_diff(
            previous_scan=baseline,
            current_scan=current_scan,
            target=target_url,
            output_dir=target_out,
        )

        # Advance baseline to current scan
        self.set_baseline(target_url, current_scan)

        return briefing

    def watch_once(
        self,
        target: Union[TargetConfig, str],
        baseline_scan: Optional[Any] = None,
        scan_fn: Optional[Callable[[TargetConfig], Any]] = None,
        output_dir: Optional[str] = None,
    ) -> WatchDiffBriefing:
        """Convenience method for a single watch verification cycle."""
        if isinstance(target, str):
            target_cfg = TargetConfig(url=target)
        else:
            target_cfg = target

        if baseline_scan is not None:
            self.set_baseline(target_cfg.url, baseline_scan)

        return self.execute_cycle(target_cfg=target_cfg, scan_fn=scan_fn, output_dir=output_dir)

    def watch_loop(
        self,
        targets: Optional[List[TargetConfig]] = None,
        scan_fn: Optional[Callable[[TargetConfig], Any]] = None,
        max_cycles: Optional[int] = None,
        stop_event: Optional[threading.Event] = None,
        on_briefing: Optional[Callable[[WatchDiffBriefing], None]] = None,
    ) -> List[WatchDiffBriefing]:
        """
        Continuous monitoring execution loop.
        Iterates over scheduled targets, runs cycles, and invokes callback.
        Terminates cleanly if max_cycles is reached or stop_event is set.
        """
        active_targets = targets or self.config.targets
        if not active_targets:
            raise ValueError("No targets configured for watch loop.")

        briefings_collected: List[WatchDiffBriefing] = []
        cycle_count = 0

        while True:
            if stop_event and stop_event.is_set():
                break

            for t in active_targets:
                if stop_event and stop_event.is_set():
                    break

                try:
                    briefing = self.execute_cycle(t, scan_fn=scan_fn)
                    briefings_collected.append(briefing)
                    if on_briefing:
                        on_briefing(briefing)
                except Exception as e:
                    # Log error and continue loop for other targets
                    sys.stderr.write(f"[!] Error monitoring {t.url}: {e}\n")

            cycle_count += 1
            if max_cycles is not None and cycle_count >= max_cycles:
                break

            # Sleep interval
            if active_targets:
                min_interval = min(t.interval_seconds for t in active_targets)
                if stop_event:
                    stop_event.wait(timeout=min_interval)
                else:
                    time.sleep(min_interval)

        return briefings_collected


# ---------------------------------------------------------------------------
# CLI Argument Parser & Runner
# ---------------------------------------------------------------------------

def build_watch_parser() -> argparse.ArgumentParser:
    """Build command-line parser for 'webripper watch'."""
    p = argparse.ArgumentParser(
        prog="webripper watch",
        description="WebRipper Watch Mode — Continuous Recon Diffing & Security Delta Briefings",
    )
    p.add_argument("target", nargs="?", default="", help="Target URL to monitor")
    p.add_argument("-t", "--target", dest="target_flag", help="Target URL to monitor")
    p.add_argument("-c", "--config", help="Path to watch configuration JSON file")
    p.add_argument("-b", "--baseline", help="Path to baseline scan JSON report")
    p.add_argument("--current", help="Path to current scan JSON report (for direct diffing)")
    p.add_argument("-i", "--interval", default="5m", help="Monitoring interval (e.g. '30s', '5m', '1h')")
    p.add_argument("-o", "--output-dir", default="webripper_watch_output", help="Directory for briefing.md and briefing.json")
    p.add_argument("--profile", choices=["quick", "standard", "aggressive"], default="standard", help="Scan intensity profile")
    p.add_argument("--once", action="store_true", help="Execute single diff cycle and exit")
    p.add_argument("--no-auth-check", action="store_true", help="Bypass ethical target authorization check")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress console briefing output")
    p.add_argument("--json", dest="json_stdout", action="store_true", help="Output change-only JSON delta to stdout")
    return p


def run_watch_cli(argv: Optional[List[str]] = None) -> int:
    """
    Clean headless API drivable via CLI 'webripper watch'.
    Returns semantic exit codes:
      0 = Clean execution, no new CRITICAL or HIGH findings
      1 = Operational error / unhandled failure / unauthorized target
      2 = Security regression detected (CRITICAL or HIGH findings)
    """
    parser = build_watch_parser()
    args = parser.parse_args(argv)

    target_url = args.target_flag or args.target
    config: Optional[WatchConfig] = None

    if args.config:
        try:
            config = parse_watch_config(args.config)
        except Exception as e:
            sys.stderr.write(f"[!] Error parsing config file: {e}\n")
            return 1

    if not config:
        if not target_url and not args.baseline:
            parser.print_usage(sys.stderr)
            sys.stderr.write("webripper watch: error: either target or --config must be provided\n")
            return 1

        try:
            interval_sec = parse_interval(args.interval)
        except ValueError as ve:
            sys.stderr.write(f"[!] Error: {ve}\n")
            return 1

        target_cfg = TargetConfig(
            url=target_url or "https://target.local",
            interval_seconds=interval_sec,
            authorised=not args.no_auth_check,
            profile=args.profile,
            output_dir=args.output_dir,
        )
        config = WatchConfig(
            targets=[target_cfg],
            default_interval_seconds=interval_sec,
            output_dir=args.output_dir,
            enforce_authorisation=not args.no_auth_check,
        )

    engine = WatchEngine(config=config, output_dir=args.output_dir)

    # Mode 1: Direct comparison between baseline and current JSON files
    if args.baseline and args.current:
        if not os.path.isfile(args.baseline):
            sys.stderr.write(f"[!] Baseline file not found: {args.baseline}\n")
            return 1
        if not os.path.isfile(args.current):
            sys.stderr.write(f"[!] Current scan file not found: {args.current}\n")
            return 1

        try:
            with open(args.baseline, "r", encoding="utf-8") as f:
                base_data = json.load(f)
            with open(args.current, "r", encoding="utf-8") as f:
                curr_data = json.load(f)
        except Exception as e:
            sys.stderr.write(f"[!] Failed to parse input scan JSON: {e}\n")
            return 1

        briefing = engine.run_diff(
            previous_scan=base_data,
            current_scan=curr_data,
            target=target_url or base_data.get("url", ""),
            output_dir=args.output_dir,
        )

        if args.json_stdout:
            print(briefing.to_json())
        elif not args.quiet:
            print(briefing.to_markdown())

        # Exit codes: 2 if new CRITICAL or HIGH findings, else 0
        return 2 if briefing.has_critical_or_high_regressions else 0

    # Mode 2: One-shot watch with baseline
    if args.once and args.baseline and target_url:
        if not os.path.isfile(args.baseline):
            sys.stderr.write(f"[!] Baseline file not found: {args.baseline}\n")
            return 1
        with open(args.baseline, "r", encoding="utf-8") as f:
            base_data = json.load(f)

        briefing = engine.run_diff(
            previous_scan=base_data,
            current_scan={"findings": [], "url": target_url},
            target=target_url,
            output_dir=args.output_dir,
        )

        if args.json_stdout:
            print(briefing.to_json())
        elif not args.quiet:
            print(briefing.to_markdown())

        return 2 if briefing.has_critical_or_high_regressions else 0

    # If --once was passed with config
    if args.once:
        briefings: List[WatchDiffBriefing] = []
        for t in config.targets:
            try:
                base = engine.get_baseline(t.url) or []
                b = engine.run_diff(base, [], target=t.url, output_dir=args.output_dir)
                briefings.append(b)
                if not args.quiet and not args.json_stdout:
                    print(b.to_markdown())
            except UnauthorizedTargetError as ute:
                sys.stderr.write(f"[!] Authorization error: {ute}\n")
                return 1

        if args.json_stdout:
            print(json.dumps([b.to_dict() for b in briefings], indent=2))

        has_critical = any(b.has_critical_or_high_regressions for b in briefings)
        return 2 if has_critical else 0

    print(f"[*] Starting WebRipper Watch Mode for {len(config.targets)} target(s)...")
    return 0
