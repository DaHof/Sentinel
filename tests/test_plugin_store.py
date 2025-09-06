import os
import tempfile
import importlib


def test_deep_merge_upgrades_missing_keys(monkeypatch):
    # Use a temp sqlite file for plugin store
    with tempfile.TemporaryDirectory() as td:
        monkeypatch.setenv("PLUGINS_DB_PATH", os.path.join(td, "plugins.db"))
        # Reload plugin_store with new env
        plugin_store = importlib.import_module("plugin_store")
        importlib.reload(plugin_store)

        default = {
            "enabled": True,
            "delivery": {
                "email": {"enabled": False, "recipients": ""},
                "slack": {"enabled": False, "webhook_url": ""},
                "teams": {"enabled": False, "webhook_url": ""},
            },
        }
        # Save a minimal config first (without teams)
        minimal = {
            "enabled": True,
            "delivery": {
                "email": {"enabled": True, "recipients": "a@b.com"},
            },
        }
        plugin_store.save_plugin("x", minimal)
        cfg = plugin_store.load_plugin("x", default)
        # Should contain the missing nested keys from default
        assert "teams" in cfg["delivery"]
        assert "slack" in cfg["delivery"]
        # And preserve previously set values
        assert cfg["delivery"]["email"]["enabled"] is True
        assert cfg["delivery"]["email"]["recipients"] == "a@b.com"

