"""
Tests for the data model classes.
"""

import json
import pytest
from app.models import (
    EventType,
    RipperSettings,
    ProgressEvent,
    FileResult,
    RipReport,
    _format_size,
)


class TestRipperSettings:
    def test_defaults(self):
        s = RipperSettings()
        assert s.url == ""
        assert s.output_dir == ""
        assert s.same_origin_only is True
        assert s.include_external is False
        assert s.max_files == 1000
        assert s.timeout == 30
        assert s.delay == 0.0
        assert s.dynamic_capture is True

    def test_custom_values(self):
        s = RipperSettings(
            url="https://example.com",
            output_dir="C:\\output",
            same_origin_only=False,
            include_external=True,
            max_files=500,
            timeout=60,
            delay=0.5,
            dynamic_capture=False,
        )
        assert s.url == "https://example.com"
        assert s.max_files == 500
        assert s.dynamic_capture is False

    def test_to_dict(self):
        s = RipperSettings(url="https://test.com", output_dir="/tmp")
        d = s.to_dict()
        assert isinstance(d, dict)
        assert d["url"] == "https://test.com"
        assert "same_origin_only" in d


class TestProgressEvent:
    def test_creation(self):
        e = ProgressEvent(
            event_type=EventType.FILE_DOWNLOADED,
            message="Downloaded /style.css",
            downloaded=5,
            failed=1,
            total=20,
            phase="Downloading",
        )
        assert e.event_type == EventType.FILE_DOWNLOADED
        assert e.downloaded == 5

    def test_event_types(self):
        assert EventType.PHASE_CHANGE.value == "phase_change"
        assert EventType.FILE_DOWNLOADED.value == "file_downloaded"
        assert EventType.FILE_FAILED.value == "file_failed"
        assert EventType.LOG.value == "log"
        assert EventType.COMPLETE.value == "complete"
        assert EventType.CANCELLED.value == "cancelled"


class TestFileResult:
    def test_creation(self):
        f = FileResult(
            url="https://example.com/style.css",
            status=200,
            size=1024,
            content_type="text/css",
            local_path="example.com/style.css",
        )
        assert f.url == "https://example.com/style.css"
        assert f.error == ""

    def test_to_dict(self):
        f = FileResult(url="https://example.com/a.js", status=404, error="Not Found")
        d = f.to_dict()
        assert d["status"] == 404
        assert d["error"] == "Not Found"


class TestRipReport:
    def test_to_json(self):
        report = RipReport(
            url="https://example.com",
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T00:01:00",
            total_downloaded=10,
            total_failed=2,
            total_size=50000,
            files=[
                FileResult(url="https://example.com/a.css", status=200, size=1000),
            ],
        )
        json_str = report.to_json()
        data = json.loads(json_str)
        assert data["url"] == "https://example.com"
        assert data["summary"]["total_downloaded"] == 10
        assert data["summary"]["total_size_human"] == "48.8 KB"
        assert len(data["files"]) == 1

    def test_empty_report(self):
        report = RipReport()
        json_str = report.to_json()
        data = json.loads(json_str)
        assert data["summary"]["total_downloaded"] == 0
        assert data["files"] == []


class TestFormatSize:
    def test_bytes(self):
        assert _format_size(0) == "0 B"
        assert _format_size(512) == "512 B"
        assert _format_size(1023) == "1023 B"

    def test_kilobytes(self):
        assert _format_size(1024) == "1.0 KB"
        assert _format_size(1536) == "1.5 KB"

    def test_megabytes(self):
        assert _format_size(1048576) == "1.0 MB"
        assert _format_size(5242880) == "5.0 MB"

    def test_gigabytes(self):
        assert _format_size(1073741824) == "1.00 GB"
