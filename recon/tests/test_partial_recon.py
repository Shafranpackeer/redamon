"""
Unit tests for Partial Recon module (recon/partial_recon.py).

Run with: python -m pytest recon/tests/test_partial_recon.py -v
"""
import sys
import os
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock, PropertyMock

# Add paths
_recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_project_root = os.path.dirname(_recon_dir)
sys.path.insert(0, _project_root)
sys.path.insert(0, _recon_dir)

# Pre-mock heavy dependencies that aren't available in the test environment
sys.modules['neo4j'] = MagicMock()

# Import only load_config at module level (doesn't trigger lazy imports)
from partial_recon import load_config


class TestLoadConfig(unittest.TestCase):
    """Tests for config loading from JSON file."""

    def test_load_valid_config(self):
        config = {"tool_id": "SubdomainDiscovery", "domain": "example.com", "user_inputs": ["api.example.com"], "dedup_enabled": True}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            f.flush()
            os.environ["PARTIAL_RECON_CONFIG"] = f.name
            try:
                result = load_config()
                self.assertEqual(result["tool_id"], "SubdomainDiscovery")
                self.assertEqual(result["domain"], "example.com")
            finally:
                del os.environ["PARTIAL_RECON_CONFIG"]
                os.unlink(f.name)

    def test_load_config_missing_env(self):
        if "PARTIAL_RECON_CONFIG" in os.environ:
            del os.environ["PARTIAL_RECON_CONFIG"]
        with self.assertRaises(SystemExit):
            load_config()

    def test_load_config_invalid_file(self):
        os.environ["PARTIAL_RECON_CONFIG"] = "/nonexistent/path.json"
        try:
            with self.assertRaises(SystemExit):
                load_config()
        finally:
            del os.environ["PARTIAL_RECON_CONFIG"]

    def test_load_config_invalid_json(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid")
            f.flush()
            os.environ["PARTIAL_RECON_CONFIG"] = f.name
            try:
                with self.assertRaises(SystemExit):
                    load_config()
            finally:
                del os.environ["PARTIAL_RECON_CONFIG"]
                os.unlink(f.name)

    def test_config_preserves_all_fields(self):
        config = {
            "tool_id": "SubdomainDiscovery",
            "domain": "test.io",
            "user_inputs": ["a.test.io", "b.test.io"],
            "dedup_enabled": False,
            "user_id": "u1",
            "webapp_api_url": "http://localhost:3000",
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config, f)
            f.flush()
            os.environ["PARTIAL_RECON_CONFIG"] = f.name
            try:
                result = load_config()
                self.assertEqual(result["domain"], "test.io")
                self.assertFalse(result["dedup_enabled"])
                self.assertEqual(len(result["user_inputs"]), 2)
                self.assertEqual(result["webapp_api_url"], "http://localhost:3000")
            finally:
                del os.environ["PARTIAL_RECON_CONFIG"]
                os.unlink(f.name)


def _mock_discover_result(subdomains=None):
    subs = subdomains or ["www.example.com", "api.example.com"]
    return {
        "metadata": {"scan_type": "subdomain_dns_discovery"},
        "domain": "example.com",
        "subdomains": subs,
        "subdomain_count": len(subs),
        "dns": {
            "domain": {"has_records": True, "records": {}, "ips": {"ipv4": ["93.184.216.34"], "ipv6": []}},
            "subdomains": {s: {"has_records": True, "records": {}, "ips": {"ipv4": ["93.184.216.34"], "ipv6": []}} for s in subs},
        },
        "external_domains": [],
        "subdomain_status_map": {s: "resolved" for s in subs},
    }


class TestRunSubdomainDiscovery(unittest.TestCase):
    """Tests for run_subdomain_discovery using module-level mocks.

    Since partial_recon.py uses lazy imports inside function bodies,
    we mock the modules in sys.modules before calling the function.
    """

    def _run_with_mocks(self, config, discover_result=None, neo4j_connected=True, puredns_result=None, resolve_dns_result=None):
        """Helper that sets up all mocks and runs run_subdomain_discovery."""
        # Mock get_settings
        mock_settings = MagicMock()
        mock_settings.return_value = {"USE_TOR_FOR_RECON": False, "USE_BRUTEFORCE_FOR_SUBDOMAINS": False}

        # Mock domain_recon functions
        mock_discover = MagicMock(return_value=discover_result or _mock_discover_result())
        mock_resolve = MagicMock(return_value=resolve_dns_result or {
            "domain": {"has_records": True, "records": {}, "ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
            "subdomains": {},
        })
        mock_puredns = MagicMock(return_value=puredns_result or [])

        # Mock Neo4jClient
        mock_client = MagicMock()
        mock_client.verify_connection.return_value = neo4j_connected
        mock_client.update_graph_from_partial_discovery.return_value = {
            "subdomains_total": 2, "subdomains_new": 2, "subdomains_existing": 0,
            "ips_total": 2, "ips_new": 2, "dns_records_created": 0, "errors": [],
        }
        mock_neo4j_cls = MagicMock()
        mock_neo4j_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_neo4j_cls.return_value.__exit__ = MagicMock(return_value=False)

        # Create mock modules
        mock_project_settings = MagicMock()
        mock_project_settings.get_settings = mock_settings

        mock_domain_recon = MagicMock()
        mock_domain_recon.discover_subdomains = mock_discover
        mock_domain_recon.resolve_all_dns = mock_resolve
        mock_domain_recon.run_puredns_resolve = mock_puredns

        mock_graph_db = MagicMock()
        mock_graph_db.Neo4jClient = mock_neo4j_cls

        # Inject mocks into sys.modules
        saved = {}
        modules_to_mock = {
            'recon.project_settings': mock_project_settings,
            'recon.domain_recon': mock_domain_recon,
            'graph_db': mock_graph_db,
        }
        for name, mod in modules_to_mock.items():
            saved[name] = sys.modules.get(name)
            sys.modules[name] = mod

        os.environ.setdefault("USER_ID", "user1")
        os.environ.setdefault("PROJECT_ID", "proj1")

        try:
            # Re-import to pick up mocked modules
            import importlib
            import partial_recon as pr
            importlib.reload(pr)
            pr.run_subdomain_discovery(config)
        finally:
            # Restore modules
            for name, mod in saved.items():
                if mod is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = mod

        return {
            "settings": mock_settings,
            "discover": mock_discover,
            "resolve_dns": mock_resolve,
            "puredns": mock_puredns,
            "neo4j_client": mock_client,
            "neo4j_cls": mock_neo4j_cls,
        }

    def test_basic_discovery_no_user_inputs(self):
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": [], "dedup_enabled": True})
        mocks["discover"].assert_called_once()
        mocks["neo4j_client"].update_graph_from_partial_discovery.assert_called_once()
        _, kw = mocks["neo4j_client"].update_graph_from_partial_discovery.call_args
        self.assertIsNone(kw.get("user_input_id"))
        self.assertTrue(kw.get("dedup_enabled"))

    def test_user_inputs_triggers_userinput_node(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["new.example.com"], "dedup_enabled": True},
            discover_result=_mock_discover_result(["www.example.com"]),
            puredns_result=["www.example.com", "new.example.com"],
            resolve_dns_result={
                "domain": {"has_records": True, "records": {}, "ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
                "subdomains": {
                    "www.example.com": {"has_records": True, "records": {}, "ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
                    "new.example.com": {"has_records": True, "records": {}, "ips": {"ipv4": ["5.6.7.8"], "ipv6": []}},
                },
            },
        )
        mocks["neo4j_client"].create_user_input_node.assert_called_once()
        _, ui_kw = mocks["neo4j_client"].create_user_input_node.call_args
        self.assertEqual(ui_kw["domain"], "example.com")
        self.assertEqual(ui_kw["user_input_data"]["values"], ["new.example.com"])
        self.assertEqual(ui_kw["user_input_data"]["tool_id"], "SubdomainDiscovery")

    def test_dedup_disabled_passed_through(self):
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": [], "dedup_enabled": False})
        _, kw = mocks["neo4j_client"].update_graph_from_partial_discovery.call_args
        self.assertFalse(kw["dedup_enabled"])

    def test_neo4j_unavailable_skips_update(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": [], "dedup_enabled": True},
            neo4j_connected=False,
        )
        mocks["neo4j_client"].update_graph_from_partial_discovery.assert_not_called()

    def test_settings_fetched_from_get_settings(self):
        mocks = self._run_with_mocks({"domain": "example.com", "user_inputs": [], "dedup_enabled": True})
        mocks["settings"].assert_called_once()

    def test_user_input_status_completed(self):
        mocks = self._run_with_mocks(
            {"domain": "example.com", "user_inputs": ["x.example.com"], "dedup_enabled": True},
            discover_result=_mock_discover_result(["www.example.com"]),
            puredns_result=["www.example.com", "x.example.com"],
            resolve_dns_result={
                "domain": {"has_records": True, "records": {}, "ips": {"ipv4": ["1.2.3.4"], "ipv6": []}},
                "subdomains": {"www.example.com": {"has_records": True, "records": {}, "ips": {"ipv4": ["1.2.3.4"], "ipv6": []}}, "x.example.com": {"has_records": True, "records": {}, "ips": {"ipv4": ["2.3.4.5"], "ipv6": []}}},
            },
        )
        mocks["neo4j_client"].update_user_input_status.assert_called_once()
        args = mocks["neo4j_client"].update_user_input_status.call_args[0]
        self.assertEqual(args[1], "completed")


if __name__ == "__main__":
    unittest.main()
