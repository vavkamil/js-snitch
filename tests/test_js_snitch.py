import os
import pytest
import json
import subprocess
from unittest.mock import patch, MagicMock, mock_open
from js_snitch import (
    extract_js_files,
    parse_trufflehog_json,
    parse_semgrep_json,
    scan_host,
    check_dependency,
    download_and_beautify,
    save_combined_findings,
    main,
    get_unique_path,
)
import requests
import tqdm


def test_extract_js_files():
    # Mock out the requests.get call so we don't do real network calls
    with patch("js_snitch.requests.get") as mock_get:
        # Create a fake HTML page with script tags
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = """
            <html>
            <body>
                <script src="script1.js"></script>
                <script src="/assets/script2.js"></script>
                <script>/* inline script */</script>
            </body>
            </html>
        """

        js_urls = extract_js_files("https://example.com")
        # We expect two .js URLs
        assert len(js_urls) == 2
        # They should be fully resolved with urljoin
        assert js_urls[0] == "https://example.com/script1.js"
        assert js_urls[1] == "https://example.com/assets/script2.js"


def test_extract_js_files_network_error():
    with patch("js_snitch.requests.get") as mock_get:
        mock_get.side_effect = requests.exceptions.RequestException("Network error")
        js_urls = extract_js_files("https://example.com")
        assert js_urls == []


def test_extract_js_files_invalid_status():
    with patch("js_snitch.requests.get") as mock_get:
        mock_get.return_value.status_code = 404
        mock_get.return_value.raise_for_status.side_effect = (
            requests.exceptions.HTTPError
        )
        js_urls = extract_js_files("https://example.com")
        assert js_urls == []


def test_parse_trufflehog_json(tmp_path):
    # Create a sample line of JSON from Trufflehog output
    sample_data = {
        "DetectorName": "GenericSecret",
        "Verified": True,
        "Raw": "some-secret-value",
        "SourceMetadata": {"Data": {"Filesystem": {"file": "test_file.js"}}},
    }

    # Write to a file in a temporary directory
    json_file = tmp_path / "trufflehog_output.json"
    with json_file.open("w", encoding="utf-8") as f:
        f.write(json.dumps(sample_data) + "\n")

    results = parse_trufflehog_json(str(json_file))
    assert len(results) == 1
    assert results[0]["filename"] == "test_file.js"
    assert results[0]["detector_name"] == "GenericSecret"
    assert results[0]["verified"] is True
    assert results[0]["raw"] == "some-secret-value"


def test_parse_trufflehog_json_invalid_json(tmp_path):
    json_file = tmp_path / "invalid.json"
    json_file.write_text("invalid json content")

    results = parse_trufflehog_json(str(json_file))
    assert results == []


def test_parse_trufflehog_json_missing_fields(tmp_path):
    # The function returns a result with empty filename when SourceMetadata is missing
    sample_data = {
        "DetectorName": "GenericSecret",
        "Verified": False,
        "Raw": "test-value",
    }

    json_file = tmp_path / "missing_fields.json"
    with json_file.open("w") as f:
        f.write(json.dumps(sample_data) + "\n")

    results = parse_trufflehog_json(str(json_file))
    assert len(results) == 1
    assert results[0] == {
        "detector_name": "GenericSecret",
        "filename": "",  # Empty filename when SourceMetadata is missing
        "raw": "test-value",
        "verified": False,
    }


def test_parse_trufflehog_json_invalid_structure(tmp_path):
    sample_data = {
        "SomeOtherField": "value"
        # Missing all required fields
    }

    json_file = tmp_path / "invalid_structure.json"
    with json_file.open("w") as f:
        f.write(json.dumps(sample_data) + "\n")

    results = parse_trufflehog_json(str(json_file))
    assert len(results) == 1
    assert results[0] == {
        "detector_name": "",
        "filename": "",
        "raw": "",
        "verified": False,
    }


# Add a new test for completely invalid JSON
def test_parse_trufflehog_json_completely_invalid(tmp_path):
    json_file = tmp_path / "invalid.json"
    json_file.write_text("not json at all")

    results = parse_trufflehog_json(str(json_file))
    assert len(results) == 0


def test_parse_trufflehog_json_file_not_exists():
    """Test parse_trufflehog_json when file doesn't exist"""
    with patch("os.path.isfile") as mock_isfile:
        mock_isfile.return_value = False  # File does not exist

        results = parse_trufflehog_json("nonexistent_file.json")
        assert results == []  # Should return empty list when file doesn't exist


def test_parse_semgrep_json(tmp_path):
    # Create a sample semgrep JSON output
    sample_data = {
        "results": [
            {
                "path": "test_file.js",
                "check_id": "rules.x.y.z.example_rule",
                "extra": {
                    "severity": "WARNING",
                    "message": "Hardcoded credential",
                    "lines": "const password = '123';",
                },
            }
        ]
    }

    json_file = tmp_path / "semgrep_output.json"
    with json_file.open("w", encoding="utf-8") as f:
        json.dump(sample_data, f)

    findings = parse_semgrep_json(str(json_file))
    assert len(findings) == 1
    assert findings[0]["path"] == "test_file.js"
    assert findings[0]["check_id"] == "rules.x.y.z.example_rule"
    assert findings[0]["severity"] == "WARNING"
    assert "Hardcoded credential" in findings[0]["message"]
    assert "password = '123';" in findings[0]["lines"]


def test_parse_semgrep_json_invalid_json(tmp_path):
    json_file = tmp_path / "invalid.json"
    json_file.write_text("invalid json content")

    results = parse_semgrep_json(str(json_file))
    assert results == []


@pytest.mark.parametrize("hostname", ["example.com", "bad-domain.xyz"])
def test_scan_host(hostname):
    """
    This is a more "integration-style" test.
    We'll patch out network calls & commands inside scan_host.
    """
    with patch("js_snitch.extract_js_files") as mock_extract, patch(
        "js_snitch.download_and_beautify"
    ) as mock_dl, patch("js_snitch.subprocess.run") as mock_subproc:
        # Mock the returned list of JS URLs
        mock_extract.return_value = ["https://example.com/script.js"]

        # We won't actually download/beautify anything, so just no-op
        mock_dl.return_value = None

        # For the subprocess calls (Trufflehog & Semgrep), do nothing
        mock_subproc.return_value = MagicMock()

        results = scan_host(hostname, minimal_output=True)
        # We can make some assertions about the structure:
        assert "total_findings" in results
        assert "verified_findings" in results
        # We know total_findings could be 0 if everything is empty or mocked
        # The key is that it doesn't crash.

        # In a real environment, you'd ensure the script writes out to an output folder, etc.
        # For now, ensure it's not throwing errors.


def test_scan_host_with_findings():
    with patch("js_snitch.extract_js_files") as mock_extract, patch(
        "js_snitch.download_and_beautify"
    ) as mock_dl, patch("js_snitch.subprocess.run") as mock_run, patch(
        "js_snitch.parse_trufflehog_json"
    ) as mock_th, patch(
        "js_snitch.parse_semgrep_json"
    ) as mock_sg:

        mock_extract.return_value = ["https://example.com/script.js"]
        mock_dl.return_value = None
        mock_run.return_value = MagicMock(returncode=0)

        # Mock some findings
        mock_th.return_value = [
            {
                "filename": "test.js",
                "detector_name": "ApiKey",
                "verified": True,
                "raw": "secret123",
            }
        ]

        mock_sg.return_value = [
            {
                "path": "test.js",
                "check_id": "rule1",
                "severity": "WARNING",
                "message": "Found secret",
                "lines": "const key = 'abc'",
            }
        ]

        result = scan_host("example.com", minimal_output=True)
        assert result["total_findings"] == 2
        assert result["verified_findings"] == 1
        assert "ApiKey" in result["detector_names"]


def test_scan_host_no_js_files():
    with patch("js_snitch.extract_js_files") as mock_extract:
        mock_extract.return_value = []
        result = scan_host("example.com", minimal_output=True)
        assert result["total_findings"] == 0
        assert result["verified_findings"] == 0


def test_check_dependency_success():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="v1.0.0\n", stderr="", returncode=0)
        version = check_dependency("test-cmd", "Test Tool", verbose=True)
        assert version == "v1.0.0"
        mock_run.assert_called_once_with(
            ["test-cmd", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )


def test_check_dependency_stderr_fallback():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", stderr="v2.0.0\n", returncode=0)
        version = check_dependency("test-cmd", "Test Tool", verbose=True)
        assert version == "v2.0.0"


def test_check_dependency_failure():
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(1, "test-cmd")
        with pytest.raises(SystemExit):
            check_dependency("test-cmd", "Test Tool")


def test_download_and_beautify(tmp_path):
    js_content = 'function test(){console.log("hello")}'
    beautified_js = 'function test() {\n    console.log("hello")\n}'

    with patch("requests.get") as mock_get, patch(
        "jsbeautifier.beautify"
    ) as mock_beautify:

        mock_get.return_value = MagicMock(content=js_content.encode(), status_code=200)
        mock_beautify.return_value = beautified_js

        tmp_dir = tmp_path / "tmp"
        beautify_dir = tmp_path / "beautify"
        tmp_dir.mkdir()
        beautify_dir.mkdir()

        download_and_beautify(
            "https://example.com/test.js", str(tmp_dir), str(beautify_dir)
        )

        # Check if files were created with correct content
        assert (tmp_dir / "test.js").read_text() == js_content
        assert (beautify_dir / "test.js").read_text() == beautified_js


def test_download_and_beautify_network_error(tmp_path):
    with patch("requests.get") as mock_get:
        mock_get.side_effect = Exception("Network error")

        tmp_dir = tmp_path / "tmp"
        beautify_dir = tmp_path / "beautify"
        tmp_dir.mkdir()
        beautify_dir.mkdir()

        # Should not raise exception
        download_and_beautify(
            "https://example.com/test.js", str(tmp_dir), str(beautify_dir)
        )

        # Files should not exist
        assert not (tmp_dir / "test.js").exists()
        assert not (beautify_dir / "test.js").exists()


def test_save_combined_findings(tmp_path):
    trufflehog_findings = [
        {
            "filename": "test1.js",
            "detector_name": "ApiKey",
            "verified": True,
            "raw": "secret123",
        }
    ]

    semgrep_findings = [
        {"path": "test2.js", "check_id": "rule1", "lines": 'const key = "abc"'}
    ]

    output_file = tmp_path / "secrets.txt"
    save_combined_findings(trufflehog_findings, semgrep_findings, str(output_file))

    content = output_file.read_text()
    assert "Trufflehog secrets:" in content
    assert "test1.js" in content
    assert "ApiKey" in content
    assert "secret123" in content
    assert "Semgrep secrets:" in content
    assert "test2.js" in content
    assert "rule1" in content
    assert 'const key = "abc"' in content


def test_save_combined_findings_empty(tmp_path):
    output_file = tmp_path / "empty_secrets.txt"
    save_combined_findings([], [], str(output_file))

    content = output_file.read_text()
    assert "Trufflehog secrets:" in content
    assert "(None)" in content
    assert "Semgrep secrets:" in content
    assert content.count("(None)") == 2


def test_main_with_host(capsys):
    test_args = ["js_snitch.py", "--host", "example.com"]
    with patch("sys.argv", test_args), patch(
        "js_snitch.check_dependency"
    ) as mock_check, patch("js_snitch.scan_host") as mock_scan:

        mock_scan.return_value = {
            "total_findings": 0,
            "verified_findings": 0,
            "detector_names": set(),
            "unverified_trufflehog": set(),
            "unverified_semgrep": set(),
            "combined_txt_path": "",
        }

        main()
        captured = capsys.readouterr()
        assert "No findings were discovered" in captured.out
        mock_scan.assert_called_once_with("example.com", minimal_output=False)


def test_main_with_invalid_args():
    test_args = ["js_snitch.py"]  # No --host or --list provided
    with patch("sys.argv", test_args), patch(
        "argparse.ArgumentParser.error"
    ) as mock_error:

        main()
        mock_error.assert_called_once_with("You must specify either --host or --list.")


def test_main_with_list(tmp_path):
    hosts_file = tmp_path / "hosts.txt"
    hosts_file.write_text("example.com\ntest.com\n")

    test_args = ["js_snitch.py", "--list", str(hosts_file)]

    with patch("sys.argv", test_args), patch(
        "js_snitch.check_dependency"
    ) as mock_check, patch("js_snitch.scan_host") as mock_scan:

        mock_scan.return_value = {
            "total_findings": 1,
            "verified_findings": 1,
            "detector_names": {"ApiKey"},
            "unverified_trufflehog": set(),
            "unverified_semgrep": set(),
            "combined_txt_path": str(tmp_path / "secrets.txt"),
        }

        main()
        assert mock_scan.call_count == 2


def test_main_with_invalid_list_file(capsys):
    test_args = ["js_snitch.py", "--list", "nonexistent.txt"]
    with patch("sys.argv", test_args), patch(
        "js_snitch.check_dependency"
    ) as mock_check:

        # Call main and catch the SystemExit
        with pytest.raises(SystemExit) as exc_info:
            main()

        # Check exit code
        assert exc_info.value.code == 1

        # Check error message
        captured = capsys.readouterr()
        assert "[-] The file nonexistent.txt does not exist." in captured.out


def test_main_debug_mode(capsys):
    test_args = ["js_snitch.py", "--debug"]
    with patch("sys.argv", test_args), patch("subprocess.run") as mock_run:

        # Mock trufflehog version
        mock_run.side_effect = [
            MagicMock(stdout="trufflehog dev\n", stderr="", returncode=0),
            MagicMock(stdout="1.103.0\n", stderr="", returncode=0),
        ]

        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "[i] TruffleHog version: trufflehog dev" in captured.out
        assert "[i] Semgrep version: 1.103.0" in captured.out
        assert "[i] Dependencies OK. Exiting now." in captured.out


def test_scan_host_with_output(capsys):
    """Test scan_host with print statements enabled"""
    with patch("js_snitch.extract_js_files") as mock_extract, patch(
        "js_snitch.download_and_beautify"
    ) as mock_dl, patch("js_snitch.subprocess.run") as mock_run, patch(
        "js_snitch.parse_trufflehog_json"
    ) as mock_th, patch(
        "js_snitch.parse_semgrep_json"
    ) as mock_sg:

        mock_extract.return_value = [
            "https://example.com/script1.js",
            "https://example.com/script2.js",
        ]
        mock_dl.return_value = None
        mock_run.return_value = MagicMock(returncode=0)

        # Mock findings
        mock_th.return_value = [
            {
                "filename": "test.js",
                "detector_name": "ApiKey",
                "verified": True,
                "raw": "secret123",
            }
        ]

        mock_sg.return_value = [
            {
                "path": "test.js",
                "check_id": "rule1",
                "severity": "WARNING",
                "message": "Found secret",
                "lines": "const key = 'abc'",
            }
        ]

        result = scan_host("example.com", minimal_output=False)

        captured = capsys.readouterr()
        assert "[i] Fetching scripts from https://example.com" in captured.out
        assert "\t[i] Found 2 JS files" in captured.out
        assert "\t[i] Downloading and beautifying ..." in captured.out
        assert "\t[i] Files are saved in" in captured.out
        assert "[i] Running TruffleHog ..." in captured.out
        assert "[i] Running Semgrep ..." in captured.out


def test_main_single_host_no_findings(capsys):
    test_args = ["js_snitch.py", "--host", "example.com"]
    with patch("sys.argv", test_args), patch("js_snitch.check_dependency"), patch(
        "js_snitch.scan_host"
    ) as mock_scan:

        mock_scan.return_value = {
            "total_findings": 0,
            "verified_findings": 0,
            "detector_names": set(),
            "unverified_trufflehog": set(),
            "unverified_semgrep": set(),
            "combined_txt_path": "",
        }

        main()

        captured = capsys.readouterr()
        assert "\n[i] No findings were discovered." in captured.out
        assert "\n[i] Have a nice day!\n" in captured.out


def test_main_single_host_with_findings(capsys):
    test_args = ["js_snitch.py", "--host", "example.com"]
    with patch("sys.argv", test_args), patch("js_snitch.check_dependency"), patch(
        "js_snitch.scan_host"
    ) as mock_scan:

        mock_scan.return_value = {
            "total_findings": 1,
            "verified_findings": 1,
            "detector_names": {"ApiKey"},
            "unverified_trufflehog": set(),
            "unverified_semgrep": set(),
            "combined_txt_path": "/tmp/secrets.txt",
        }

        main()

        captured = capsys.readouterr()
        assert "\n[i] Done; findings saved to /tmp/secrets.txt" in captured.out
        assert "\n[i] Have a nice day!\n" in captured.out


def test_banner(capsys):
    """Test that banner prints correctly"""
    from js_snitch import banner

    banner()
    captured = capsys.readouterr()
    assert "v0.1" in captured.out


def test_download_and_beautify_unique_files(tmp_path):
    """Test that download_and_beautify handles duplicate filenames correctly"""
    urls = [
        "https://example.com/script.js",  # Normal case
        "https://example.com/script.js?v=1",  # Same name with query param
        "https://example.com/path/",  # Empty basename
        "https://example.com/script",  # No extension
    ]

    with patch("requests.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            content=b'console.log("test")',
            raise_for_status=lambda: None,
        )

        tmp_dir = tmp_path / "tmp"
        beautify_dir = tmp_path / "beautify"
        tmp_dir.mkdir()
        beautify_dir.mkdir()

        # Try to download all files
        for url in urls:
            download_and_beautify(url, str(tmp_dir), str(beautify_dir))

        # Check files in tmp directory
        tmp_files = list(tmp_dir.glob("*.js"))
        assert len(tmp_files) == len(urls)  # Each URL should create a unique file
        assert len(set(f.name for f in tmp_files)) == len(
            urls
        )  # All filenames should be unique

        # Check files in beautify directory
        beautify_files = list(beautify_dir.glob("*.js"))
        assert len(beautify_files) == len(urls)
        assert len(set(f.name for f in beautify_files)) == len(urls)

        # Verify content of files
        for js_file in beautify_files:
            content = js_file.read_text(encoding="utf-8")
            assert 'console.log("test")' in content


def test_get_unique_path():
    with patch("os.path.exists") as mock_exists:
        # Test when file doesn't exist
        mock_exists.return_value = False
        path = get_unique_path("/tmp/test.js")
        assert path == "/tmp/test.js"

        # Test when file exists but first alternative doesn't
        mock_exists.side_effect = [True, False]
        path = get_unique_path("/tmp/test.js")
        assert path == "/tmp/test_1.js"

        # Test when multiple files exist
        mock_exists.side_effect = [True, True, True, False]
        path = get_unique_path("/tmp/test.js")
        assert path == "/tmp/test_3.js"


def test_main_with_list_multiple_hosts(capsys):
    """Test multi-host mode with various findings scenarios"""
    hosts_content = "example.com\ntest.com\nempty.com\n"

    with patch("builtins.open", mock_open(read_data=hosts_content)), patch(
        "os.path.isfile"
    ) as mock_isfile, patch("js_snitch.check_dependency"), patch(
        "js_snitch.scan_host"
    ) as mock_scan, patch(
        "tqdm.tqdm"
    ) as mock_tqdm, patch(
        "sys.argv", ["js_snitch.py", "--list", "hosts.txt"]
    ):

        mock_isfile.return_value = True

        # Mock different results for different hosts
        mock_scan.side_effect = [
            # Host with verified findings
            {
                "total_findings": 2,
                "verified_findings": 1,
                "detector_names": {"ApiKey"},
                "unverified_trufflehog": {"GenericSecret"},
                "unverified_semgrep": {"hardcoded_secret"},
                "combined_txt_path": "/tmp/example_secrets.txt",
            },
            # Host with only unverified findings
            {
                "total_findings": 1,
                "verified_findings": 0,
                "detector_names": set(),
                "unverified_trufflehog": {"GenericSecret"},
                "unverified_semgrep": set(),
                "combined_txt_path": "/tmp/test_secrets.txt",
            },
            # Host with no findings
            {
                "total_findings": 0,
                "verified_findings": 0,
                "detector_names": set(),
                "unverified_trufflehog": set(),
                "unverified_semgrep": set(),
                "combined_txt_path": "",
            },
        ]

        main()

        captured = capsys.readouterr()
        # Check findings output
        assert "[!] Findings:" in captured.out
        assert "[✓] example.com (1/2) [ApiKey]" in captured.out
        assert "unverified: GenericSecret, hardcoded_secret" in captured.out
        assert "[!] test.com (0/1)" in captured.out
        assert "unverified: GenericSecret" in captured.out
        # empty.com should be skipped (no findings)
        assert "empty.com" not in captured.out
        assert "[i] Have a nice day!" in captured.out


def test_scan_host_with_semgrep_findings(capsys):
    """Test scan_host with Semgrep findings and output"""
    with patch("js_snitch.extract_js_files") as mock_extract, patch(
        "js_snitch.download_and_beautify"
    ), patch("js_snitch.subprocess.run"), patch(
        "js_snitch.parse_trufflehog_json"
    ) as mock_th, patch(
        "js_snitch.parse_semgrep_json"
    ) as mock_sg:

        mock_extract.return_value = ["https://example.com/script.js"]
        mock_th.return_value = []  # No TruffleHog findings

        # Mock Semgrep findings with different rule IDs
        mock_sg.return_value = [
            {
                "path": "test.js",
                "check_id": "rules.secrets.hardcoded_password",
                "severity": "WARNING",
                "message": "Found hardcoded password",
                "lines": "const password = '123'",
            },
            {
                "path": "test.js",
                "check_id": "rules.secrets.api_key",
                "severity": "WARNING",
                "message": "Found API key",
                "lines": "const apiKey = 'xyz'",
            },
        ]

        result = scan_host("example.com", minimal_output=False)

        captured = capsys.readouterr()
        assert "\t[!] Found 2 findings from Semgrep." in captured.out
        assert "\t[!] Unverified: api_key, hardcoded_password" in captured.out


def test_download_and_beautify_error_handling(tmp_path):
    """Test error handling in download_and_beautify"""
    tmp_dir = tmp_path / "tmp"
    beautify_dir = tmp_path / "beautify"
    tmp_dir.mkdir()
    beautify_dir.mkdir()

    with patch("requests.get") as mock_get:
        # Test network error
        mock_get.side_effect = requests.exceptions.RequestException
        download_and_beautify(
            "https://example.com/error.js", str(tmp_dir), str(beautify_dir)
        )
        assert len(list(tmp_dir.glob("*.js"))) == 0

        # Test invalid JS content
        mock_get.side_effect = None
        mock_get.return_value = MagicMock(
            status_code=200, content=b"Invalid JS", raise_for_status=lambda: None
        )
        download_and_beautify(
            "https://example.com/invalid.js", str(tmp_dir), str(beautify_dir)
        )
        assert len(list(beautify_dir.glob("*.js"))) == 1


def test_banner(capsys):
    """Test banner display"""
    from js_snitch import banner

    banner()
    captured = capsys.readouterr()
    assert "v0.1" in captured.out


def test_scan_host_no_js_files_with_output(capsys):
    """Test scan_host with no JS files and output message"""
    with patch("js_snitch.extract_js_files") as mock_extract:
        mock_extract.return_value = []
        result = scan_host("example.com", minimal_output=False)

        captured = capsys.readouterr()
        assert "No JavaScript files found or page retrieval failed." in captured.out
        assert result["total_findings"] == 0


def test_scan_host_trufflehog_verified_propagation():
    """Test that verified status propagates in TruffleHog results"""
    with patch("js_snitch.extract_js_files") as mock_extract, patch(
        "js_snitch.download_and_beautify"
    ), patch("js_snitch.subprocess.run"), patch(
        "js_snitch.parse_trufflehog_json"
    ) as mock_th, patch(
        "js_snitch.parse_semgrep_json"
    ) as mock_sg:

        mock_extract.return_value = ["https://example.com/script.js"]
        # Two findings with same raw value, second one verified
        mock_th.return_value = [
            {
                "filename": "test1.js",
                "detector_name": "ApiKey",
                "verified": False,
                "raw": "same-secret",
            },
            {
                "filename": "test2.js",
                "detector_name": "ApiKey",
                "verified": True,
                "raw": "same-secret",
            },
        ]
        mock_sg.return_value = []

        result = scan_host("example.com", minimal_output=True)
        assert result["verified_findings"] == 1
        assert result["total_findings"] == 1  # Deduplicated


def test_scan_host_unverified_trufflehog_output(capsys):
    """Test unverified TruffleHog findings output"""
    with patch("js_snitch.extract_js_files") as mock_extract, patch(
        "js_snitch.download_and_beautify"
    ), patch("js_snitch.subprocess.run"), patch(
        "js_snitch.parse_trufflehog_json"
    ) as mock_th, patch(
        "js_snitch.parse_semgrep_json"
    ) as mock_sg:

        mock_extract.return_value = ["https://example.com/script.js"]
        mock_th.return_value = [
            {
                "filename": "test.js",
                "detector_name": "ApiKey",
                "verified": False,
                "raw": "secret123",
            }
        ]
        mock_sg.return_value = []

        result = scan_host("example.com", minimal_output=False)

        captured = capsys.readouterr()
        assert "\t[!] Unverified: ApiKey" in captured.out


def test_scan_host_no_semgrep_findings(capsys):
    """Test output when no Semgrep findings are found"""
    with patch("js_snitch.extract_js_files") as mock_extract, patch(
        "js_snitch.download_and_beautify"
    ), patch("js_snitch.subprocess.run"), patch(
        "js_snitch.parse_trufflehog_json"
    ) as mock_th, patch(
        "js_snitch.parse_semgrep_json"
    ) as mock_sg:

        mock_extract.return_value = ["https://example.com/script.js"]
        mock_th.return_value = []
        mock_sg.return_value = []

        result = scan_host("example.com", minimal_output=False)

        captured = capsys.readouterr()
        assert "\t[!] No Semgrep findings found." in captured.out


def test_parse_trufflehog_json_empty_line():
    """Test parse_trufflehog_json with empty lines"""
    mock_data = '\n  \n{"DetectorName": "test", "Verified": false, "Raw": "test-value", "SourceMetadata": {"Data": {"Filesystem": {"file": "test.js"}}}}\n'

    with patch("builtins.open", mock_open(read_data=mock_data)), patch(
        "os.path.isfile"
    ) as mock_isfile:

        mock_isfile.return_value = True  # Make the file appear to exist

        results = parse_trufflehog_json("fake_path")
        assert len(results) == 1
        assert results[0]["detector_name"] == "test"
        assert results[0]["filename"] == "test.js"
        assert results[0]["raw"] == "test-value"
        assert results[0]["verified"] is False
