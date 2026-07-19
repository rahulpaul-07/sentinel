"""Unit tests for the read-only tool layer."""

import pytest

from sentinel.tools import Tools

TARGET = "targets/vulnerable_app"


def test_path_safety_blocks_escape():
    # The agent must never read outside the target directory.
    tools = Tools(TARGET)
    with pytest.raises(ValueError):
        tools.read_file("../../etc/passwd")


def test_list_files_finds_app():
    assert "app.py" in Tools(TARGET).list_files()


def test_grep_finds_execute():
    matches = Tools(TARGET).grep(r"\.execute\(")
    assert any(m.path == "app.py" for m in matches)