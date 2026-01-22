"""Tests for Nuclei tool integration."""
import pytest
from unittest.mock import Mock, patch
from strix.tools.nuclei.nuclei_actions import nuclei_scan


class TestNucleiScan:
    """Test suite for nuclei_scan function."""

    @patch("strix.tools.nuclei.nuclei_actions.subprocess.run")
    def test_successful_scan_with_findings(self, mock_run):
        """Test successful scan that returns findings."""
        # Mock subprocess result with JSON findings
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = '{"info":{"severity":"high","name":"Test Vuln"}}\n{"info":{"severity":"critical","name":"Critical Vuln"}}'
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        result = nuclei_scan(
            target="https://example.com",
            scan_type="cve",
            severity="critical,high"
        )

        assert result["exit_code"] == 0
        assert result["total_findings"] == 2
        assert result["summary"]["high"] == 1
        assert result["summary"]["critical"] == 1
        assert result["target"] == "https://example.com"
        assert result["scan_type"] == "cve"
        assert result["error"] is None

    @patch("strix.tools.nuclei.nuclei_actions.subprocess.run")
    def test_scan_with_no_findings(self, mock_run):
        """Test scan that returns no findings."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        result = nuclei_scan(target="https://example.com", scan_type="vulnerabilities")

        assert result["exit_code"] == 0
        assert result["total_findings"] == 0
        assert len(result["findings"]) == 0

    @patch("strix.tools.nuclei.nuclei_actions.subprocess.run")
    def test_nuclei_not_installed(self, mock_run):
        """Test error handling when nuclei is not installed."""
        mock_run.side_effect = FileNotFoundError()

        result = nuclei_scan(target="https://example.com", scan_type="cve")

        assert result["exit_code"] == -1
        assert "not installed" in result["error"]
        assert result["total_findings"] == 0

    @patch("strix.tools.nuclei.nuclei_actions.subprocess.run")
    def test_scan_timeout(self, mock_run):
        """Test handling of scan timeout."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=[], timeout=60)

        result = nuclei_scan(target="https://example.com", scan_type="cve", timeout=60)

        assert result["exit_code"] == -1
        assert "timed out" in result["error"]
        assert result["total_findings"] == 0

    def test_scan_type_mapping(self):
        """Test that different scan types use correct templates."""
        with patch("strix.tools.nuclei.nuclei_actions.subprocess.run") as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            # Test CVE scan type
            nuclei_scan(target="https://example.com", scan_type="cve")
            call_args = mock_run.call_args[0][0]
            assert "-t" in call_args
            assert "cves/" in call_args

            # Test exposed panels scan type
            nuclei_scan(target="https://example.com", scan_type="exposed_panels")
            call_args = mock_run.call_args[0][0]
            assert "exposed-panels/" in call_args

    def test_severity_filter(self):
        """Test that severity filter is properly applied."""
        with patch("strix.tools.nuclei.nuclei_actions.subprocess.run") as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            nuclei_scan(
                target="https://example.com",
                scan_type="cve",
                severity="critical,high"
            )

            call_args = mock_run.call_args[0][0]
            assert "-s" in call_args
            assert "critical,high" in call_args

    def test_tags_filter(self):
        """Test that tags filter is properly applied."""
        with patch("strix.tools.nuclei.nuclei_actions.subprocess.run") as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            nuclei_scan(
                target="https://example.com",
                scan_type="vulnerabilities",
                tags="xss,sqli,rce"
            )

            call_args = mock_run.call_args[0][0]
            assert "-tags" in call_args
            assert "xss,sqli,rce" in call_args
