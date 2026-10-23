"""Fuzz tests for SMDA label providers using Hypothesis.

Targets GoLabelProvider and Delphi providers with malformed binary data
for their entry-point methods.
"""

from hypothesis import given, settings
from hypothesis.strategies import binary

from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.DelphiKbSymbolProvider import DelphiKbSymbolProvider
from smda.common.labelprovider.DelphiPythiaProvider import DelphiPythiaProvider
from smda.common.labelprovider.GoLabelProvider import GoSymbolProvider
from smda.SmdaConfig import SmdaConfig
from smda.utility.DelphiKbFileLoader import DelphiKbFileLoader

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
    """DelphiKB isCompatible and update must not crash on arbitrary data."""
    result = DelphiKbFileLoader.isCompatible(data)
    assert isinstance(result, bool)
    binary_info = BinaryInfo(data)
    delphi_kb_provider.update(binary_info)
    assert isinstance(delphi_kb_provider.getFunctionSymbols(), dict)


@given(data=binary(max_size=4096))
@settings(max_examples=500)
def test_delphi_pythia_update_missing_sections_never_crashes(data):
    """DelphiPythiaProvider's update must not crash on data with no sections.
    A SmdaConfig is needed for the provider constructor."""
    config = SmdaConfig()
    provider = DelphiPythiaProvider(config)
    binary_info = BinaryInfo(data)
    binary_info.bitness = 32
    provider.update(binary_info)
    assert isinstance(provider.getFunctionSymbols(), dict)
