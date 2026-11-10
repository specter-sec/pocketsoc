from pathlib import Path

import pytest
import yaml

from pocketsoc.cli import instance_lock, main
from pocketsoc.config import load_config, require_safe_bind

ROOT = Path(__file__).resolve().parents[1]


def write_config(tmp_path, **changes):
    data = yaml.safe_load((ROOT / "config.yaml").read_text())
    data.update(changes)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


def test_safe_defaults_and_check(capsys):
    config = load_config(ROOT / "config.yaml")
    assert not config.capture_passwords and not config.telegram["enabled"]
    require_safe_bind(config, False)
    assert main(["check", "--config", str(ROOT / "config.yaml")]) == 0
    assert "No sockets opened" in capsys.readouterr().out


def test_public_bind_requires_explicit_flag(tmp_path):
    path = write_config(tmp_path, listeners=[{"protocol": "http", "host": "0.0.0.0", "port": 8080}])
    config = load_config(path)
    with pytest.raises(ValueError, match="allow-network"):
        require_safe_bind(config, False)
    require_safe_bind(config, True)


@pytest.mark.parametrize(
    "change",
    [
        {"privacy": {"capture_passwords": "false"}},
        {"listeners": [{"protocol": "ssh", "host": "localhost", "port": 2222}]},
        {"listeners": [{"protocol": "http", "host": "127.0.0.1", "port": 80}]},
        {"rules": [{"id": "bad", "pattern": "[", "severity": "high"}]},
        {"telegram": {"enabled": True, "max_per_minute": 1000}},
    ],
)
def test_invalid_config_rejected(tmp_path, change):
    with pytest.raises(ValueError):
        load_config(write_config(tmp_path, **change))


def test_unsafe_yaml_clean_error(tmp_path, capsys):
    path = tmp_path / "unsafe.yaml"
    path.write_text("!!python/object/apply:os.system ['echo must-not-run']")
    assert main(["check", "--config", str(path)]) == 2
    assert "PocketSOC:" in capsys.readouterr().err


def test_demo_is_offline_and_writes_both_formats(tmp_path):
    assert main(["demo", "--output-dir", str(tmp_path)]) == 0
    assert "SYNTHETIC DEMO" in (tmp_path / "summary-2026-01-15.html").read_text()
    assert (tmp_path / "summary-2026-01-15.md").exists()


def test_single_instance_lock(tmp_path):
    with instance_lock(tmp_path / "pocketsoc.lock"):
        with pytest.raises(ValueError, match="already running"):
            with instance_lock(tmp_path / "pocketsoc.lock"):
                pass
