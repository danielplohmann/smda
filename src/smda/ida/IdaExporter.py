from smda.export.Exporter import Exporter

from .IdaInterface import IdaInterface


class IdaExporter(Exporter):
    """The export engine bound to the running IDA, kept for callers that predate smda.export."""

    def __init__(self, config, bitness=None, ida_interface=None):
        super().__init__(config, ida_interface if ida_interface is not None else IdaInterface(), bitness=bitness)

    @property
    def ida_interface(self):
        return self.interface

    @ida_interface.setter
    def ida_interface(self, interface):
        self.interface = interface
