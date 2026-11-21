"""
Tests for URL extraction from HTML, JavaScript, CSS, and source maps.
These test the static extraction methods of the WebRipper class.
"""

import pytest
from app.ripper import WebRipper, _normalize_url, _sanitize_path
from app.models import RipperSettings


def make_ripper(url="https://example.com"):
    """Create a WebRipper instance for testing."""
    settings = RipperSettings(url=url, output_dir="/tmp/test")
    ripper = WebRipper(settings=settings, progress_callback=lambda e: None)
    return ripper


# Expose discovered_urls as a shortcut
def _discovered(ripper):
    return ripper._discovered


class TestHtmlExtraction:
    """Test URL extraction from HTML content."""

    def _parse(self, ripper, html, base="https://example.com"):
        """Set root HTML and parse it."""
        ripper._root_html = html
        ripper._parse_html()

    def test_script_src(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><head><script src="/js/app.js"></script></head><body></body></html>')
        assert "https://example.com/js/app.js" in _discovered(ripper)

    def test_link_stylesheet(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><head><link rel="stylesheet" href="/css/style.css"></head></html>')
        assert "https://example.com/css/style.css" in _discovered(ripper)

    def test_img_src(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><img src="/images/logo.png"></body></html>')
        assert "https://example.com/images/logo.png" in _discovered(ripper)

    def test_img_srcset(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><img srcset="/img/small.jpg 1x, /img/large.jpg 2x"></body></html>')
        assert "https://example.com/img/small.jpg" in _discovered(ripper)
        assert "https://example.com/img/large.jpg" in _discovered(ripper)

    def test_img_data_src(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><img data-src="/images/lazy.jpg"></body></html>')
        assert "https://example.com/images/lazy.jpg" in _discovered(ripper)

    def test_video_src(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><video src="/media/clip.mp4" poster="/media/poster.jpg"></video></body></html>')
        assert "https://example.com/media/clip.mp4" in _discovered(ripper)
        assert "https://example.com/media/poster.jpg" in _discovered(ripper)

    def test_audio_src(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><audio src="/audio/track.mp3"></audio></body></html>')
        assert "https://example.com/audio/track.mp3" in _discovered(ripper)

    def test_source_tag(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><video><source src="/media/video.webm"></video></body></html>')
        assert "https://example.com/media/video.webm" in _discovered(ripper)

    def test_iframe_src(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><iframe src="/embed/widget.html"></iframe></body></html>')
        assert "https://example.com/embed/widget.html" in _discovered(ripper)

    def test_link_preload(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><head><link rel="preload" href="/fonts/main.woff2" as="font"></head></html>')
        assert "https://example.com/fonts/main.woff2" in _discovered(ripper)

    def test_link_manifest(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><head><link rel="manifest" href="/manifest.json"></head></html>')
        assert "https://example.com/manifest.json" in _discovered(ripper)

    def test_link_icon(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><head><link rel="icon" href="/favicon.png"></head></html>')
        assert "https://example.com/favicon.png" in _discovered(ripper)

    def test_meta_og_image(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><head><meta property="og:image" content="https://example.com/og.jpg"></head></html>')
        assert "https://example.com/og.jpg" in _discovered(ripper)

    def test_object_data(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><object data="/flash/game.swf"></object></body></html>')
        assert "https://example.com/flash/game.swf" in _discovered(ripper)

    def test_embed_src(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><embed src="/plugin/viewer.pdf"></body></html>')
        assert "https://example.com/plugin/viewer.pdf" in _discovered(ripper)

    def test_data_background(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><div data-background="/images/bg.jpg"></div></body></html>')
        assert "https://example.com/images/bg.jpg" in _discovered(ripper)

    def test_relative_url_resolution(self):
        ripper = make_ripper("https://example.com/page/about.html")
        ripper._root_html = '<html><body><img src="images/photo.jpg"></body></html>'
        ripper._parse_html()
        assert "https://example.com/page/images/photo.jpg" in _discovered(ripper)

    def test_ignores_data_urls(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><img src="data:image/png;base64,abc123"></body></html>')
        assert len([u for u in _discovered(ripper) if u.startswith("data:")]) == 0

    def test_ignores_javascript_urls(self):
        ripper = make_ripper()
        self._parse(ripper, '<html><body><a href="javascript:void(0)">click</a></body></html>')
        assert len([u for u in _discovered(ripper) if u.startswith("javascript:")]) == 0


class TestInlineScriptExtraction:
    """Test URL extraction from inline JavaScript."""

    def _parse(self, ripper, html):
        ripper._root_html = html
        ripper._parse_html()

    def test_es_import(self):
        ripper = make_ripper()
        html = """<html><body><script>
        import { App } from './components/App.js';
        import styles from '/css/main.css';
        </script></body></html>"""
        self._parse(ripper, html)
        assert "https://example.com/components/App.js" in _discovered(ripper)
        assert "https://example.com/css/main.css" in _discovered(ripper)

    def test_dynamic_import(self):
        ripper = make_ripper()
        html = """<html><body><script>
        const module = import('/chunks/lazy-module.js');
        </script></body></html>"""
        self._parse(ripper, html)
        assert "https://example.com/chunks/lazy-module.js" in _discovered(ripper)

    def test_require(self):
        ripper = make_ripper()
        html = """<html><body><script>
        const lib = require('./lib/utils.js');
        </script></body></html>"""
        self._parse(ripper, html)
        assert "https://example.com/lib/utils.js" in _discovered(ripper)

    def test_fetch_call(self):
        ripper = make_ripper()
        html = """<html><body><script>
        fetch('/api/data.json').then(r => r.json());
        </script></body></html>"""
        self._parse(ripper, html)
        assert "https://example.com/api/data.json" in _discovered(ripper)

    def test_url_pattern(self):
        ripper = make_ripper()
        html = """<html><body><script>
        var chunkUrl = "/static/js/chunk-vendor.abc123.js";
        </script></body></html>"""
        self._parse(ripper, html)
        assert "https://example.com/static/js/chunk-vendor.abc123.js" in _discovered(ripper)


class TestInlineStyleExtraction:
    """Test URL extraction from inline CSS."""

    def _parse(self, ripper, html):
        ripper._root_html = html
        ripper._parse_html()

    def test_css_url(self):
        ripper = make_ripper()
        html = """<html><head><style>
        body { background: url('/images/bg.jpg'); }
        </style></head></html>"""
        self._parse(ripper, html)
        assert "https://example.com/images/bg.jpg" in _discovered(ripper)

    def test_css_import(self):
        ripper = make_ripper()
        html = """<html><head><style>
        @import '/css/reset.css';
        </style></head></html>"""
        self._parse(ripper, html)
        assert "https://example.com/css/reset.css" in _discovered(ripper)


class TestJsContentExtraction:
    """Test URL extraction from external JS file content."""

    def test_sourcemap_comment(self):
        ripper = make_ripper()
        js_content = """
        // application code
        //# sourceMappingURL=app.js.map
        """
        ripper._scan_js(js_content, "https://example.com/js/app.js")
        assert "https://example.com/js/app.js.map" in _discovered(ripper)

    def test_js_imports(self):
        ripper = make_ripper()
        js_content = """
        import { helper } from './helpers.js';
        const chunk = import('./chunks/page-home.js');
        """
        ripper._scan_js(js_content, "https://example.com/js/main.js")
        assert "https://example.com/js/helpers.js" in _discovered(ripper)
        assert "https://example.com/js/chunks/page-home.js" in _discovered(ripper)


class TestCssContentExtraction:
    """Test URL extraction from external CSS file content."""

    def test_css_url_references(self):
        ripper = make_ripper()
        css_content = """
        @font-face {
            font-family: 'Custom';
            src: url('../fonts/custom.woff2') format('woff2');
        }
        .hero { background-image: url('/images/hero.webp'); }
        """
        ripper._scan_css(css_content, "https://example.com/css/style.css")
        assert "https://example.com/fonts/custom.woff2" in _discovered(ripper)
        assert "https://example.com/images/hero.webp" in _discovered(ripper)

    def test_css_import(self):
        ripper = make_ripper()
        css_content = """
        @import url('components.css');
        @import 'variables.css';
        """
        ripper._scan_css(css_content, "https://example.com/css/main.css")
        assert "https://example.com/css/components.css" in _discovered(ripper)
        assert "https://example.com/css/variables.css" in _discovered(ripper)

    def test_css_sourcemap(self):
        ripper = make_ripper()
        css_content = """
        body { color: red; }
        /*# sourceMappingURL=style.css.map */
        """
        ripper._scan_css(css_content, "https://example.com/css/style.css")
        assert "https://example.com/css/style.css.map" in _discovered(ripper)


class TestSourceMapExtraction:
    """Test extraction of original sources from source map JSON."""

    def test_sources_content(self):
        ripper = make_ripper()
        sourcemap_json = """{
            "version": 3,
            "sources": ["../src/App.tsx", "../src/index.tsx"],
            "sourcesContent": ["const App = () => <div/>;", "import App from './App';"],
            "mappings": "AAAA"
        }"""
        import asyncio
        loop = asyncio.new_event_loop()
        loop.run_until_complete(
            ripper._handle_source_map(sourcemap_json, "https://example.com/js/app.js.map")
        )
        loop.close()
        # sourcesContent should have been saved as files
        assert ripper._downloaded_count == 2

    def test_empty_sources_content(self):
        ripper = make_ripper()
        sourcemap_json = '{"version": 3, "sources": ["a.js"], "mappings": "AAAA"}'
        import asyncio
        loop = asyncio.new_event_loop()
        loop.run_until_complete(
            ripper._handle_source_map(sourcemap_json, "https://example.com/app.js.map")
        )
        loop.close()
        # No sourcesContent, but sources should be discovered
        assert "https://example.com/a.js" in _discovered(ripper)

    def test_invalid_json(self):
        ripper = make_ripper()
        import asyncio
        loop = asyncio.new_event_loop()
        loop.run_until_complete(
            ripper._handle_source_map("not json", "https://example.com/app.js.map")
        )
        loop.close()
        # Should not crash
        assert ripper._downloaded_count == 0
