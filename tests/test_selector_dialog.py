from gui.vault_selector_dialog import VaultSelectorDialog
from core.config import ConfigManager

def test_vault_selector_add_to_recent(tmp_path, qapp):
    cfg = ConfigManager(str(tmp_path / "cfg.json"))
    selector = VaultSelectorDialog(cfg)
    selector.add_to_recent("/fake/path.db")
    recent = selector._get_recent_list()
    assert "/fake/path.db" in recent