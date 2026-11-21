"""
Tests for URL-to-local-path sanitization.
"""

import pytest
from pathlib import Path
from app.ripper import WebRipper, _normalize_url, _sanitize_path
from app.models import RipperSettings


def make_ripper(url="https://example.com", output_dir="C:\\output"):
    settings = RipperSettings(url=url, output_dir=output_dir)
    return WebRipper(settings=settings, progress_callback=lambda e: None)


class TestSanitizePath:
    """Test the _sanitize_path module-level function."""

    def test_basic_path(self):
        path = _sanitize_path(
            "https://example.com/css/style.css", "C:\\output"
        )
        assert "example.com" in path
        assert path.endswith("style.css")

    def test_directory_url_gets_index(self):
        path = _sanitize_path(
            "https://example.com/about/", "C:\\output"
        )
        assert path.endswith("index.html")

    def test_root_url_gets_index(self):
        path = _sanitize_path(
            "https://example.com/", "C:\\output"
        )
        assert path.endswith("index.html")

    def test_path_traversal_prevention(self):
        path = _sanitize_path(
            "https://example.com/../../etc/passwd", "C:\\output"
        )
        assert ".." not in path
        assert path.startswith("C:\\output")

    def test_encoded_backslash_traversal_prevention(self):
        path = _sanitize_path(
            "https://example.com/..%5C..%5Cevil.bat", "C:\\output"
        )
        assert ".." not in path
        assert path.startswith("C:\\output")

    def test_windows_reserved_chars(self):
        path = _sanitize_path(
            "https://example.com/file<name>.txt", "C:\\output"
        )
        assert "<" not in path
        assert ">" not in path

    def test_query_string_handling(self):
        path = _sanitize_path(
            "https://example.com/api/data?format=json&v=2", "C:\\output"
        )
        assert "example.com" in path
        # Query should be incorporated as a hash in the filename
        assert "__" in Path(path).name

    def test_long_path_truncation(self):
        long_name = "a" * 300
        path = _sanitize_path(
            f"https://example.com/{long_name}.js", "C:\\output"
        )
        # Each path component should be truncated to 200 chars max
        for part in Path(path).parts:
            assert len(part) <= 210  # tolerance for extension

    def test_host_based_subfolder(self):
        path = _sanitize_path(
            "https://cdn.example.com/lib/react.js", "C:\\output"
        )
        assert "cdn.example.com" in path

    def test_preserves_directory_structure(self):
        path = _sanitize_path(
            "https://example.com/assets/js/vendor/lodash.min.js", "C:\\output"
        )
        path_fwd = path.replace("\\", "/")
        assert "assets/js/vendor/lodash.min.js" in path_fwd


class TestNormalizeUrl:
    """Test URL normalization."""

    def test_relative_to_absolute(self):
        url = _normalize_url("/style.css", "https://example.com/page/about")
        assert url == "https://example.com/style.css"

    def test_dot_relative(self):
        url = _normalize_url("./img.png", "https://example.com/page/about.html")
        assert url == "https://example.com/page/img.png"

    def test_fragment_removed(self):
        url = _normalize_url("/page#top", "https://example.com")
        assert "#" not in url

    def test_non_http_returns_none(self):
        assert _normalize_url("ftp://example.com/file", "https://example.com") is None
        assert _normalize_url("mailto:test@test.com", "https://example.com") is None

    def test_data_url_returns_none(self):
        assert _normalize_url("data:image/png;base64,abc", "https://example.com") is None

    def test_blob_url_returns_none(self):
        assert _normalize_url("blob:https://example.com/uuid", "https://example.com") is None

    def test_empty_returns_none(self):
        assert _normalize_url("", "https://example.com") is None


class TestSameOriginCheck:
    """Test same-origin filtering logic via the _filter_urls method."""

    @staticmethod
    def _prepare(ripper):
        """Set _origin so _filter_urls works outside of run()."""
        from urllib.parse import urlparse
        parsed = urlparse(ripper._base_url)
        ripper._origin = f"{parsed.scheme}://{parsed.netloc}"

    def test_same_origin_included(self):
        ripper = make_ripper("https://example.com")
        self._prepare(ripper)
        ripper._discovered.add("https://example.com/page.html")
        filtered = ripper._filter_urls()
        assert "https://example.com/page.html" in filtered

    def test_different_host_excluded_when_same_origin(self):
        ripper = make_ripper("https://example.com")
        self._prepare(ripper)
        ripper._settings.same_origin_only = True
        ripper._settings.include_external = False
        ripper._discovered.add("https://other.com/page.html")
        filtered = ripper._filter_urls()
        assert "https://other.com/page.html" not in filtered

    def test_different_host_included_when_not_same_origin(self):
        ripper = make_ripper("https://example.com")
        self._prepare(ripper)
        ripper._settings.same_origin_only = False
        ripper._discovered.add("https://cdn.other.com/img.png")
        filtered = ripper._filter_urls()
        assert "https://cdn.other.com/img.png" in filtered

    def test_max_files_cap(self):
        ripper = make_ripper("https://example.com")
        self._prepare(ripper)
        ripper._settings.max_files = 5
        for i in range(20):
            ripper._discovered.add(f"https://example.com/file{i}.js")
        filtered = ripper._filter_urls()
        assert len(filtered) == 5
