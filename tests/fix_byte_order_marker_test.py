from __future__ import annotations

from pre_commit_hooks import fix_byte_order_marker


def test_failure(tmpdir):
    f = tmpdir.join("f.txt")
    f.write_text("ohai", encoding="utf-8-sig")
    assert fix_byte_order_marker.main((str(f),)) == 1


def test_success(tmpdir):
    f = tmpdir.join("f.txt")
    f.write_text("ohai", encoding="utf-8")
    assert fix_byte_order_marker.main((str(f),)) == 0
