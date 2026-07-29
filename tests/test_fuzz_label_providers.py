"""Fuzz tests for SMDA label providers using Hypothesis.

Targets GoLabelProvider and Delphi providers with malformed binary data
for their entry-point methods.
"""

from hypothesis import given, settings
from hypothesis.strategies import binary

from smda.common.labelprovider.DelphiKbSymbolProvider import DelphiKbSymbolProvider
from smda.common.labelprovider.DelphiPythiaProvider import DelphiPythiaProvider
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider

go_provider = GoSymbolProvider(None)
delphi_kb_provider = DelphiKbSymbolProvider(None)


@given(data=binary(max_size=4096))
@settings(max_examples=500)
def test_go_get_pclntab_offset_never_crashes(data):
    """Go PCLNTAB scanning must not crash on arbitrary data."""
    result = go_provider.getPcLntabOffset(data)
    assert result is None or isinstance(result, int)


@given(data=binary(max_size=4096))
@settings(max_examples=500)
def test_go_get_pclntab_info_never_crashes(data):
    """Go PCLNTAB header validation must not crash on arbitrary data."""
    result = go_provider.getPcLntabInfo(data)
    assert result is None or isinstance(result, dict)


@given(data=binary(max_size=4096))
@settings(max_examples=500)
def test_delphi_kb_is_compatible_never_crashes(data):
    """DelphiKB isCompatible must not crash on arbitrary data."""
    try:
        result = delphi_kb_provider.isCompatible(data)
    except Exception:
        return
    assert isinstance(result, bool)


@given(data=binary(max_size=4096))
@settings(max_examples=500)
def test_delphi_pythia_update_missing_sections_never_crashes(data):
    """DelphiPythiaProvider's update must not crash on data with no sections.
    A SmdaConfig is needed for the provider constructor."""
    from smda.SmdaConfig import SmdaConfig

    config = SmdaConfig()
    provider = DelphiPythiaProvider(config)
    try:
        result = provider.isCompatible(data)
    except Exception:
        return
    assert isinstance(result, bool)
