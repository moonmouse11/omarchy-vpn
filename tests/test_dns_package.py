"""DNS lives in one package, without pulling user code into root imports."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dns_package_initializer_has_no_import_side_effects():
    package = ROOT / "src/vpn_dns"
    assert package.is_dir(), "DNS modules must live in their own package"
    tree = ast.parse((package / "__init__.py").read_text())
    assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) for node in ast.walk(tree))


def test_root_install_lists_only_trusted_dns_submodules():
    script = (ROOT / "install.sh").read_text()
    for name in ("__init__", "control", "resolvers", "profiles", "runtime"):
        assert f"vpn_dns/{name}.py" in script
    for name in ("bootstrap", "routes", "identity", "wire"):
        assert f"vpn_dns/{name}.py" not in script
