"""Central IDA backend selection and compatibility policy."""

import importlib.util

from .IdaDomainInterface import IdaDomainInterface, IdaDomainUnavailableError
from .IdaIdapythonInterface import Ida73Interface, Ida74Interface, Ida85Interface

IDA_DOMAIN_MIN_SDK_VERSION = 910

_IDAPYTHON_BACKENDS = (
    (850, Ida85Interface),
    (740, Ida74Interface),
    (0, Ida73Interface),
)


def getIdaSdkVersion():
    try:
        import idaapi
    except ImportError as exc:
        raise ImportError("The SMDA IDA backend must be run from IDA Pro.") from exc

    sdk_version = idaapi.IDA_SDK_VERSION
    if not isinstance(sdk_version, int):
        raise ValueError("Unsupported IDA SDK version")
    return sdk_version


def _getDomainInterface():
    try:
        domain_spec = importlib.util.find_spec("ida_domain")
    except (ImportError, ValueError):
        return None
    if domain_spec is None:
        return None
    return IdaDomainInterface


def _selectBackend(sdk_version, domain_interface=None):
    if not isinstance(sdk_version, int):
        raise ValueError("Unsupported IDA SDK version")
    if sdk_version >= IDA_DOMAIN_MIN_SDK_VERSION and domain_interface is not None:
        return domain_interface
    for minimum_sdk_version, backend in _IDAPYTHON_BACKENDS:
        if sdk_version >= minimum_sdk_version:
            return backend
    raise ValueError(f"Unsupported IDA SDK version: {sdk_version}")


class IdaInterface:
    instance = None

    def __init__(self):
        if not IdaInterface.instance:
            sdk_version = getIdaSdkVersion()
            domain_interface = _getDomainInterface() if sdk_version >= IDA_DOMAIN_MIN_SDK_VERSION else None
            backend = _selectBackend(sdk_version, domain_interface)
            try:
                IdaInterface.instance = backend()
            except IdaDomainUnavailableError:
                if backend is not domain_interface:
                    raise
                IdaInterface.instance = _selectBackend(sdk_version)()

    def __getattr__(self, name):
        return getattr(self.instance, name)

    @classmethod
    def fromPath(cls, input_path, save_on_close=False):
        domain_interface = _getDomainInterface()
        if domain_interface is None:
            raise ImportError(
                "Headless IDA export requires IDA Pro 9.1+ and the optional ida-domain dependency. "
                "Install it with 'pip install \"smda[ida]\"'."
            )
        return domain_interface.fromPath(input_path, save_on_close=save_on_close)
