import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

SCHEMES = ("itanium", "msvc", "rust", "swift")

SHADOW_MODULE = textwrap.dedent(
    """
    from demangle.core.plugin import LanguagePlugin


    def _refuse(*args):
        raise RuntimeError("an advertised plugin answered")


    itanium, msvc, rust, swift = (
        LanguagePlugin(name=name, detect=lambda mangled: True, parse=_refuse)
        for name in ("itanium", "msvc", "rust", "swift")
    )
    """
)

LABELS = textwrap.dedent(
    """
    import importlib

    from demangle.core import registry

    from smda.common.labelprovider.ItaniumDemangler import demangle_itanium_symbol
    from smda.common.labelprovider.MachoDemangler import demangle_macho_symbol
    from smda.common.labelprovider.MsvcDemangler import demangle_msvc_symbol
    from smda.common.labelprovider.rust_demangler import demangle

    print(demangle_itanium_symbol("_Z14shadow_checkedv"))
    print(demangle_msvc_symbol("?shadow_checked@@YAXXZ"))
    print(demangle("_RNvC6shadow7checked"))
    print(demangle_macho_symbol("_$s6shadow7checkedyyF"))
    for name in {schemes}:
        print(registry.get(name) is importlib.import_module("demangle.schemes." + name).PLUGIN)
    """
).format(schemes=SCHEMES)


class DemangleSchemeTestSuite(unittest.TestCase):
    def test_a_plugin_advertising_a_builtin_name_does_not_replace_it(self):
        with tempfile.TemporaryDirectory() as root:
            dist_info = Path(root, "shadow_schemes-0.dist-info")
            dist_info.mkdir()
            (dist_info / "METADATA").write_text("Metadata-Version: 2.1\nName: shadow-schemes\nVersion: 0\n")
            entry_points = "".join(f"{name} = shadow_schemes:{name}\n" for name in SCHEMES)
            (dist_info / "entry_points.txt").write_text("[demangle.languages]\n" + entry_points)
            Path(root, "shadow_schemes.py").write_text(SHADOW_MODULE)
            env = dict(os.environ, PYTHONPATH=os.pathsep.join([root, *sys.path]))
            result = subprocess.run(
                [sys.executable, "-c", LABELS], capture_output=True, text=True, env=env, check=False, timeout=60
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "shadow_checked()",
                "void __cdecl shadow_checked(void)",
                "shadow::checked",
                "shadow.checked() -> ()",
                *["True"] * len(SCHEMES),
            ],
        )
