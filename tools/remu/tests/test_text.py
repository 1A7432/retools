"""String extraction heuristics."""

from remu.text import find_strings, render


def wide(s):
    return s.encode("utf-16le") + b"\0\0"


def test_real_text_is_found():
    for s in ["Hello 世界", "中文", "Привет мир", "naïve café", "한국어", "“quoted”", "解密后的字符串"]:
        assert [t for _, k, t in find_strings(wide(s))] == [s], s
    assert find_strings(b"plain ascii here\0") == [(0, "a", "plain ascii here")]


def test_noise_is_not_text():
    # ASCII read as UTF-16, odd-offset UTF-16, pointer-like pairs
    assert find_strings(b"Hello\0world\0\0") == [(0, "a", "Hello"), (6, "a", "world")]
    assert find_strings(wide("煮@댋@")) == []
    soup = (0x0040B30B).to_bytes(4, "little") + (0x21000040).to_bytes(4, "little") * 2
    assert find_strings(soup, 3, lambda v: 0x400000 <= v < 0x22000000) == []


def test_render_views():
    v = render(wide("ok") + b"\0" * 4)
    assert v["wstr"] == "ok" and v["text"].startswith("o.k.")
    assert render(b"abc\0zz")["cstr"] == "abc"
