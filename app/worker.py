"""
Background worker thread for running the ripper + scanners + tools + correlator.
Bridges async ripper with pure-Python callback signals.
"""

import asyncio
import threading
import traceback
from datetime import datetime
from typing import Any, Callable, List, Optional
from urllib.parse import urlparse

from .models import (
    RipperSettings, ProgressEvent, EventType,
    RipReport, ReconReport, Severity,
)
from .ripper import WebRipper


class CallbackSignal:
    """Pure-Python callback signal dispatcher (zero-Qt dependency)."""

    def __init__(self):
        self._callbacks: List[Callable] = []
        self._lock = threading.Lock()

    def connect(self, slot: Callable) -> None:
        if not callable(slot):
            raise TypeError("Signal slot must be a callable")
        with self._lock:
            if slot not in self._callbacks:
                self._callbacks.append(slot)

    def disconnect(self, slot: Optional[Callable] = None) -> None:
        with self._lock:
            if slot is None:
                self._callbacks.clear()
            elif slot in self._callbacks:
                self._callbacks.remove(slot)

    def emit(self, *args: Any, **kwargs: Any) -> None:
        with self._lock:
            handlers = list(self._callbacks)
        for h in handlers:
            try:
                h(*args, **kwargs)
            except Exception:
                pass


class RipperWorker(threading.Thread):
    """
    Runs the WebRipper extraction engine + scanner pipeline + external tools
    + correlation engine in a pure Python background thread (headless & agent-native).

    Signals:
        progress: Emits ProgressEvent updates during the rip/scan.
        finished: Emits the final ReconReport when done.
        error: Emits an error message string on fatal failure.
    """

    def __init__(self, settings: RipperSettings, parent=None):
        super().__init__(daemon=True)
        self.progress = CallbackSignal()
        self.finished = CallbackSignal()
        self.error = CallbackSignal()
        self.settings = settings
        self._ripper: WebRipper | None = None
        self.report: ReconReport | None = None  # stored for CLI access
        self._is_cancelled = False
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._lock = threading.Lock()

    def pause(self):
        """Pause worker thread execution."""
        self._pause_event.clear()

    def resume(self):
        """Resume worker thread execution."""
        self._pause_event.set()

    def is_paused(self) -> bool:
        """Check if worker is currently paused."""
        return not self._pause_event.is_set()

    def cancel(self):
        """Signal the ripper and scanners to stop immediately."""
        with self._lock:
            self._is_cancelled = True
            self._pause_event.set()  # Unblock if paused
            if self._ripper is not None:
                self._ripper.cancel()

    def _emit_cancelled(self) -> None:
        """Emit cancellation progress event."""
        self._on_progress(ProgressEvent(
            event_type=EventType.CANCELLED,
            message="Reconnaissance mission aborted by operator.",
            phase="Aborted",
        ))

    def run(self):
        """Thread entry point. Runs crawl then scanners then tools then correlator."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            start_time = datetime.now().isoformat()

            targets = [t.strip() for t in self.settings.multi_targets if t.strip()]
            if not targets:
                targets = [self.settings.url] if self.settings.url else []
            elif self.settings.url and self.settings.url not in targets:
                targets = [self.settings.url] + targets

            if not targets:
                self.error.emit("No valid target URL specified.")
                return

            # Primary recon report
            recon = ReconReport(
                url=targets[0],
                start_time=start_time,
                settings=self.settings.to_dict(),
            )

            for i, target_url in enumerate(targets):
                if self._is_cancelled:
                    self._emit_cancelled()
                    return

                self._pause_event.wait()

                if len(targets) > 1:
                    self._on_progress(ProgressEvent(
                        event_type=EventType.PHASE_CHANGE,
                        message=f"Target [{i+1}/{len(targets)}]: {target_url}",
                        phase=f"Target {i+1}/{len(targets)}",
                    ))

                # Configure settings for this target
                import copy
                target_settings = copy.deepcopy(self.settings)
                target_settings.url = target_url

                # Phase 1: Crawl
                with self._lock:
                    if self._is_cancelled:
                        self._emit_cancelled()
                        return
                    self._ripper = WebRipper(
                        settings=target_settings,
                        progress_callback=self._on_progress,
                    )
                    if self._is_cancelled:
                        self._ripper.cancel()
                        self._emit_cancelled()
                        return

                rip_report = loop.run_until_complete(self._ripper.run())

                if self._is_cancelled:
                    self._emit_cancelled()
                    return

                self._pause_event.wait()

                if i == 0:
                    recon.rip_report = rip_report
                elif rip_report:
                    if recon.rip_report is None:
                        recon.rip_report = rip_report
                    else:
                        recon.rip_report.files.extend(rip_report.files)
                        recon.rip_report.captured_requests.extend(rip_report.captured_requests)
                        recon.rip_report.pages_crawled += rip_report.pages_crawled
                        recon.rip_report.total_downloaded += rip_report.total_downloaded
                        recon.rip_report.total_failed += rip_report.total_failed
                        recon.rip_report.total_size += rip_report.total_size

                # Phase 2: Run scanners for this target with target_settings
                self._run_scanners(recon, rip_report, target_settings)
                # Restore the worker thread's event loop in case an async scanner replaced/closed it
                try:
                    if loop.is_closed():
                        loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                except Exception:
                    pass

                if self._is_cancelled:
                    self._emit_cancelled()
                    return

                self._pause_event.wait()

            # Phase 3: Detect and run external tools
            if self.settings.use_external_tools and self.settings.profile != "quick":
                self._run_external_tools(recon)

            if self._is_cancelled:
                self._on_progress(ProgressEvent(
                    event_type=EventType.CANCELLED,
                    message="Reconnaissance mission aborted by operator.",
                    phase="Aborted",
                ))
                return

            self._pause_event.wait()

            # Phase 4: Correlate findings into attack chains
            self._on_progress(ProgressEvent(
                event_type=EventType.PHASE_CHANGE,
                message="Correlating findings into attack chains",
                phase="Correlating",
            ))
            try:
                from .correlator import correlate
                chains = correlate(recon)
                recon.attack_chains = chains
                self._on_progress(ProgressEvent(
                    event_type=EventType.CORRELATION_COMPLETE,
                    message=f"Found {len(chains)} attack chains",
                ))
            except Exception as exc:
                self._on_progress(ProgressEvent(
                    event_type=EventType.LOG,
                    message=f"Correlation error: {exc}",
                ))

            recon.end_time = datetime.now().isoformat()

            if self._is_cancelled:
                self._on_progress(ProgressEvent(
                    event_type=EventType.CANCELLED,
                    message="Reconnaissance mission aborted by operator.",
                    phase="Aborted",
                ))
                return

            self._pause_event.wait()

            # Phase 4.5: AI Threat Narrative & Executive Summary (if enabled)
            if self.settings.enable_ai:
                self._on_progress(ProgressEvent(
                    event_type=EventType.PHASE_CHANGE,
                    message="AI analyzing attack surface and synthesizing executive threat narrative",
                    phase="AI Analysis",
                ))
                try:
                    from .ai import AIAgent, AgentToolbox, OllamaClient
                    client = OllamaClient(
                        base_url=self.settings.ai_endpoint,
                        model=self.settings.ai_model,
                        timeout=self.settings.timeout,
                    )
                    if client.is_server_running(timeout=1.5):
                        toolbox = AgentToolbox(
                            output_dir=self.settings.output_dir,
                            recon_report=recon,
                            burp_proxy=self.settings.proxy,
                        )
                        agent = AIAgent(toolbox=toolbox, client=client)
                        recon.ai_summary = agent.generate_executive_report()
                        self._on_progress(ProgressEvent(
                            event_type=EventType.LOG,
                            message="AI executive threat narrative generated successfully",
                        ))
                    else:
                        self._on_progress(ProgressEvent(
                            event_type=EventType.LOG,
                            message=f"AI endpoint {self.settings.ai_endpoint} not reachable; skipping AI summary",
                        ))
                except Exception as ai_err:
                    self._on_progress(ProgressEvent(
                        event_type=EventType.LOG,
                        message=f"AI generation notice: {ai_err}",
                    ))

            if self._is_cancelled:
                self._on_progress(ProgressEvent(
                    event_type=EventType.CANCELLED,
                    message="Reconnaissance mission aborted by operator.",
                    phase="Aborted",
                ))
                return

            self._pause_event.wait()

            # Phase 5: Generate HTML/JSON reports
            self._on_progress(ProgressEvent(
                event_type=EventType.PHASE_CHANGE,
                message="Generating reports",
                phase="Generating reports",
            ))

            try:
                from .report import save_report
                save_report(recon, self.settings.output_dir)
            except Exception as exc:
                self._on_progress(ProgressEvent(
                    event_type=EventType.LOG,
                    message=f"Report generation error: {exc}",
                ))

            self.report = recon
            self.finished.emit(recon)

        except Exception as e:
            tb = traceback.format_exc()
            self.error.emit(f"{e}\n\n{tb}")

        finally:
            try:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
            finally:
                try:
                    loop.close()
                except Exception:
                    pass

    def _on_progress(self, event: ProgressEvent):
        """Forward progress events from the ripper to callback signals."""
        self.progress.emit(event)

    def _run_scanners(
        self,
        recon: ReconReport,
        rip_report: RipReport,
        settings: Optional[RipperSettings] = None,
    ) -> None:
        """Run all enabled security scanners using target-specific configuration."""
        scanners = []
        cfg = settings or self.settings
        profile = cfg.profile
        active_set = {s.strip().lower() for s in getattr(cfg, "active_scanners", []) if s.strip()}

        # Original scanners (always run)
        if cfg.scan_secrets:
            try:
                from .scanners.secrets import SecretScanner
                scanners.append(SecretScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_headers:
            try:
                from .scanners.headers import HeaderScanner
                scanners.append(HeaderScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_tech:
            try:
                from .scanners.tech import TechScanner
                scanners.append(TechScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_endpoints:
            try:
                from .scanners.endpoints import EndpointScanner
                scanners.append(EndpointScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_paths:
            try:
                from .scanners.paths import PathScanner
                scanners.append(PathScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        # New v4.0 scanners
        if cfg.scan_cors:
            try:
                from .scanners.cors import CORSScanner
                scanners.append(CORSScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_javascript:
            try:
                from .scanners.javascript import JavaScriptScanner
                scanners.append(JavaScriptScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_forms:
            try:
                from .scanners.forms import FormScanner
                scanners.append(FormScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_tls:
            try:
                from .scanners.tls import TLSScanner
                scanners.append(TLSScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_cookies:
            try:
                from .scanners.cookies import CookieScanner
                scanners.append(CookieScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_subdomains and (profile != "quick" or "subdomains" in active_set):
            try:
                from .scanners.subdomains import SubdomainScanner
                scanners.append(SubdomainScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_ports and (profile != "quick" or "portscan" in active_set or "ports" in active_set):
            try:
                from .scanners.portscan import PortScanner
                scanners.append(PortScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        # New v5.0 scanners
        if cfg.scan_waf:
            try:
                from .scanners.waf import WAFScanner
                scanners.append(WAFScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_dns and (profile != "quick" or "dns" in active_set):
            try:
                from .scanners.dns import DNSScanner
                scanners.append(DNSScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_emails:
            try:
                from .scanners.emails import EmailHarvester
                scanners.append(EmailHarvester(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_screenshots and (profile != "quick" or "screenshots" in active_set):
            try:
                from .scanners.screenshots import ScreenshotScanner
                scanners.append(ScreenshotScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        if cfg.scan_github_dork and (profile == "aggressive" or "github_dork" in active_set):
            try:
                from .scanners.github_dork import GitHubDorkScanner
                scanners.append(GitHubDorkScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        # CVE mapper — runs before vulns so we have tech context
        if cfg.scan_cves:
            try:
                from .scanners.cves import CVEScanner
                scanners.append(CVEScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        # Active vulnerability scanner — sends payloads, only on standard+aggressive or explicit
        if cfg.scan_vulns and (profile != "quick" or "vulns" in active_set):
            try:
                from .scanners.vulns import VulnScanner
                scanners.append(VulnScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        # Scenario Intelligence Scanner (#21) — Bug bounty canary probes
        if getattr(cfg, "scan_scenarios", True):
            try:
                from .scanners.scenarios import ScenarioScanner
                scanners.append(ScenarioScanner(rip_report, cfg, self._on_progress))
            except ImportError:
                pass

        # Selective scanner filtering if active_scanners list is configured
        if active_set:
            scanners = [
                s for s in scanners
                if s.name.lower() in active_set or (s.name.lower() == "portscan" and "ports" in active_set)
            ]

        for scanner in scanners:
            scanner._recon = recon
            self._pause_event.wait()
            if self._is_cancelled:
                self._on_progress(ProgressEvent(
                    event_type=EventType.LOG,
                    message="Audit scan aborted by operator.",
                ))
                break

            self._on_progress(ProgressEvent(
                event_type=EventType.PHASE_CHANGE,
                message=f"Running {scanner.name} scanner",
                phase=f"Scanning: {scanner.name}",
            ))
            try:
                result = scanner.scan()
                recon.scan_results.append(result)
                count = len(result.findings)
                self._on_progress(ProgressEvent(
                    event_type=EventType.SCAN_COMPLETE,
                    message=f"{scanner.name}: {count} findings ({result.critical_count} critical, {result.high_count} high)",
                ))
            except Exception as exc:
                self._on_progress(ProgressEvent(
                    event_type=EventType.LOG,
                    message=f"Scanner error ({scanner.name}): {exc}",
                ))

    def _run_external_tools(self, recon: ReconReport) -> None:
        """Detect and run external security tools."""
        self._pause_event.wait()
        if self._is_cancelled:
            return

        self._on_progress(ProgressEvent(
            event_type=EventType.PHASE_CHANGE,
            message="Detecting external security tools",
            phase="External tools",
        ))

        # Detect installed tools
        try:
            from .tools.detector import detect_all_tools
            tool_statuses = detect_all_tools()
            recon.tool_status = tool_statuses

            installed = [t for t in tool_statuses if t.installed]
            not_installed = [t for t in tool_statuses if not t.installed]

            self._on_progress(ProgressEvent(
                event_type=EventType.TOOL_PROGRESS,
                message=f"Tools detected: {len(installed)} installed, {len(not_installed)} missing",
            ))

            for t in installed:
                self._on_progress(ProgressEvent(
                    event_type=EventType.LOG,
                    message=f"  ● {t.name} {t.version} — {t.path}",
                ))
            for t in not_installed:
                self._on_progress(ProgressEvent(
                    event_type=EventType.LOG,
                    message=f"  ○ {t.name} — not installed" + (f" (downloadable)" if t.installable else ""),
                ))

        except Exception as exc:
            self._on_progress(ProgressEvent(
                event_type=EventType.LOG,
                message=f"Tool detection error: {exc}",
            ))
            return

        if self._is_cancelled:
            return

        # Run tools
        try:
            from .tools.runner import run_all_tools

            # Collect endpoints from existing scan results
            endpoints = []
            for sr in recon.scan_results:
                for f in sr.findings:
                    if f.url and "?" in f.url and "=" in f.url:
                        endpoints.append(f.url)

            parsed = urlparse(recon.url or self.settings.url)
            target = parsed.netloc or recon.url or self.settings.url

            findings, manual_cmds = run_all_tools(
                target=target,
                output_dir=self.settings.output_dir,
                endpoints=endpoints,
                timeout=self.settings.tool_timeout,
                progress_cb=lambda msg: self._on_progress(ProgressEvent(
                    event_type=EventType.TOOL_PROGRESS,
                    message=msg,
                )),
            )

            # Add tool findings as a scan result
            if findings:
                from .models import ScanResult
                recon.scan_results.append(ScanResult(
                    scanner_name="external_tools",
                    description="Findings from external security tools (nmap, nikto, nuclei, etc.)",
                    findings=findings,
                ))

            recon.tool_commands = manual_cmds

            self._on_progress(ProgressEvent(
                event_type=EventType.TOOL_COMPLETE,
                message=f"External tools: {len(findings)} findings, {len(manual_cmds)} manual commands generated",
            ))

        except Exception as exc:
            self._on_progress(ProgressEvent(
                event_type=EventType.LOG,
                message=f"Tool runner error: {exc}",
            ))
