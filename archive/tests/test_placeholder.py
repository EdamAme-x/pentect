from engine.categories import Category
from engine.placeholder import make_placeholder


def test_same_value_gives_same_placeholder():
    p1 = make_placeholder(Category.CREDENTIAL, "secret-token-1")
    p2 = make_placeholder(Category.CREDENTIAL, "secret-token-1")
    assert p1 == p2


def test_different_values_differ():
    p1 = make_placeholder(Category.CREDENTIAL, "secret-token-1")
    p2 = make_placeholder(Category.CREDENTIAL, "secret-token-2")
    assert p1 != p2


def test_placeholder_format():
    p = make_placeholder(Category.INTERNAL_URL, "jira.corp.internal")
    assert p.startswith("<<")
    assert p.endswith(">>")
    body = p[2:-2]
    label, _, h = body.rpartition("_")
    assert label
    assert len(h) == 8
    assert all(c in "0123456789abcdef" for c in h)
