#!/usr/bin/python

import datetime
import logging
from typing import TYPE_CHECKING, Any, Optional, Union

if TYPE_CHECKING:
    from dnfile import dnPE
import dnfile
import dnfile.mdtable
from dncil.cil.body import CilMethodBody
from dncil.cil.body.reader import CilMethodBodyReaderBase
from dncil.clr.token import InvalidToken, StringToken, Token
from dnfile.enums import MetadataTables

from smda.common.ExceptionHandling import reraise_non_operational_exception
from smda.common.labelprovider.CilSymbolProvider import CilSymbolProvider
from smda.DisassemblyResult import DisassemblyResult

from .FunctionAnalysisState import FunctionAnalysisState

LOGGER = logging.getLogger(__name__)
DOTNET_META_TABLES_BY_INDEX = {table.value: table.name for table in MetadataTables}


def read_dotnet_user_string(pe, token: StringToken) -> Union[str, InvalidToken]:
    """read user string from #US stream"""
    user_string_heap = getattr(pe.net, "user_strings", None)
    if user_string_heap is None:
        return InvalidToken(token.value)
    try:
        user_string: Optional[dnfile.stream.UserString] = user_string_heap.get(token.rid)
    except UnicodeDecodeError:
        return InvalidToken(token.value)

    if user_string is None or (isinstance(user_string, bytes) or user_string.value is None):
        return InvalidToken(token.value)

    return user_string.value


def resolve_token(pe, token: Token) -> Any:
    """ """
    if isinstance(token, StringToken):
        return read_dotnet_user_string(pe, token)

    table_name: str = DOTNET_META_TABLES_BY_INDEX.get(token.table, "")
    if not table_name:
        # table_index is not valid
        return InvalidToken(token.value)

    table: Any = getattr(pe.net.mdtables, table_name, None)
    if table is None:
        # table index is valid but table is not present
        return InvalidToken(token.value)

    try:
        return table.rows[token.rid - 1]
    except IndexError:
        # table index is valid but row index is not valid
        return InvalidToken(token.value)


def format_operand(pe, operand: Any) -> str:
    """ """
    if isinstance(operand, Token):
        operand = resolve_token(pe, operand)
    if isinstance(operand, str):
        return f'"{operand}"'
    elif isinstance(operand, int):
        return hex(operand)
    elif isinstance(operand, list):
        return f"[{', '.join([f'({x:04X})' for x in operand])}]"
    elif isinstance(operand, dnfile.mdtable.MemberRefRow):
        if isinstance(operand.Class.row, (dnfile.mdtable.TypeRefRow,)):
            return f"{str(operand.Class.row.TypeNamespace)}.{operand.Class.row.TypeName}::{operand.Name}"
        else:
            return f"{operand.Name}"
    elif isinstance(operand, dnfile.mdtable.MethodSpecRow):
        operand = operand.Method.row
        if isinstance(operand, (dnfile.mdtable.TypeRefRow,)):
            return f"{str(operand.TypeNamespace)}.{operand.TypeName}::{operand.Name}"
        else:
            return f"{operand.Name}"
    elif isinstance(operand, (dnfile.mdtable.TypeRefRow, dnfile.mdtable.TypeDefRow)):
        return f"{str(operand.TypeNamespace)}.{operand.TypeName}"
    elif isinstance(operand, dnfile.mdtable.TypeSpecRow):
        # a TypeSpec has no name, only a signature blob; render the blob so distinct
        # instantiations stay distinguishable without serializing a memory address
        signature = getattr(operand.Signature, "value", None)
        return f"TypeSpec({signature.hex()})" if signature else "TypeSpec()"
    elif isinstance(operand, (dnfile.mdtable.FieldRow, dnfile.mdtable.MethodDefRow)):
        return f"{operand.Name}"
    elif operand is None:
        return ""

    # never fall through to str(operand): the default object repr embeds a memory address,
    # which made every report of the same input serialize differently
    return f"<{type(operand).__name__}>"


class DnfileMethodBodyReader(CilMethodBodyReaderBase):
    def __init__(self, pe, row):
        """ """
        self.pe: dnPE = pe
        self.offset: int = self.pe.get_offset_from_rva(row.Rva)

    def read(self, n: int) -> bytes:
        """ """
        data: bytes = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return data

    def tell(self) -> int:
        """ """
        return self.offset

    def seek(self, rva: int) -> int:
        """ """
        self.offset = rva
        return self.offset


class CilDisassembler:
    def __init__(self, config):
        self.config = config
        self._tfidf = None
        self.binary_info = None
        self.label_providers = []
        self.cil_label_provider = CilSymbolProvider(self.config)
        self._addLabelProviders()
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = config.VERSION
        self.disassembly.setConfidenceThreshold(config.CONFIDENCE_THRESHOLD)

    def addPdbFile(self, binary_info, pdb_path):
        return

    def _addLabelProviders(self):
        self.label_providers.append(self.cil_label_provider)

    def _updateLabelProviders(self, binary_info):
        for provider in self.label_providers:
            try:
                provider.update(binary_info)
            except Exception as exc:
                reraise_non_operational_exception(exc)
                LOGGER.error("Label provider %s failed to update: %r", provider.__class__.__name__, exc)

    def resolveSymbol(self, address):
        for provider in self.label_providers:
            if not provider.isSymbolProvider():
                continue
            result = provider.getSymbol(address)
            if result:
                return result
        return ""

    def _updateApiInformation(self, from_addr, ins_bytes, api_function):
        if ins_bytes.endswith(b"\x0a"):
            if api_function.startswith("<"):
                # format_operand could not resolve the row to a name, so there is no API here
                return
            self.disassembly.addr_to_api[from_addr] = api_function

    @staticmethod
    def _seedExceptionHandlerBlocks(state, method_body):
        """Seed try/handler/filter entries as block starts.

        A catch/finally/filter entry has no intra-method branch pointing at it, so
        getBlocks() - which starts blocks only at code_start_addr and jump_targets - would
        never open a block there. dncil reports these offsets relative to the start of the
        code, while instruction offsets are absolute, so rebase them onto code_start_addr.
        """
        handlers = getattr(method_body, "exception_handlers", None) or []
        code_start = state.code_start_addr
        for handler in handlers:
            for offset in (handler.try_start, handler.handler_start, getattr(handler, "filter_start", -1)):
                if offset is not None and offset >= 0:
                    state.jump_targets.add(code_start + offset)

    def analyzeFunction(self, pe, start_addr, method_body):
        LOGGER.debug("analyzeFunction() starting analysis of candidate @0x%08x", start_addr)
        state = FunctionAnalysisState(start_addr, method_body.instructions[0].offset, self.disassembly)
        self._seedExceptionHandlerBlocks(state, method_body)
        for insn in method_body.instructions:
            state.setNextInstructionReachable(True)
            i_bytes = insn.get_bytes()
            i_address = insn.offset
            i_size = len(i_bytes)
            i_mnemonic = str(insn.opcode)
            i_op_str = format_operand(pe, insn.operand)
            # https://en.wikipedia.org/wiki/List_of_CIL_instructions
            if i_mnemonic in ["ret", "endfinally", "endfilter"]:
                state.setNextInstructionReachable(False)
            if i_mnemonic in [
                "beq",
                "beq.s",
                "bge",
                "bge.s",
                "bge.un",
                "bge.un.s",
                "bgt",
                "bgt.s",
                "bgt.un",
                "bgt.un.s",
                "ble",
                "ble.s",
                "ble.un",
                "ble.un.s",
                "blt",
                "blt.s",
                "blt.un",
                "blt.un.s",
                "bne.un",
                "bne.un.s",
                "br",
                "br.s",
                "brfalse",
                "brfalse.s",
                "brinst",
                "brinst.s",
                "brnull",
                "brnull.s",
                "brtrue",
                "brtrue.s",
                "brzero",
                "brzero.s",
                "leave",
                "leave.s",
            ]:
                target = int(i_op_str, 16)
                state.addCodeRef(i_address, target, by_jump=True)
                # an unconditional branch does not fall through; leaving reachability set
                # emitted a bogus edge to the next instruction, which addCodeRef then also
                # registered as a jump target (is_jmp was just set by the branch itself)
                if i_mnemonic in ["br", "br.s", "leave", "leave.s"]:
                    state.setNextInstructionReachable(False)
            if i_mnemonic in ["jmp"]:
                # jmp's operand is InlineMethod (a tail-jump to another method), not a
                # same-function branch offset, so i_op_str is usually a method name/token
                # string here rather than a hex address like the branches above.
                state.setNextInstructionReachable(False)
                try:
                    target = int(i_op_str, 16)
                except ValueError:
                    pass
                else:
                    state.addCodeRef(i_address, target, by_jump=True)
            if i_mnemonic in ["ldstr"]:
                # we possibly want to extract and collect these and put them in the stringref part of SmdaFunction
                # format_operand only wraps the operand in quotes when the resolved user string
                # is a str; an unreadable #US entry falls through to str(InvalidToken), where
                # the unconditional [1:-1] would chop two real characters off the string ref
                string_ref = i_op_str[1:-1] if i_op_str.startswith('"') and i_op_str.endswith('"') else i_op_str
                self.disassembly.addStringRef(start_addr, i_address, string_ref)
            if i_mnemonic in ["call", "calli", "callvirt"]:
                self._updateApiInformation(i_address, i_bytes, i_op_str)
                # https://blog.objektkultur.de/about-tail-recursion-in-.net/
                if state.prev_opcode.startswith("tail"):
                    state.setNextInstructionReachable(False)
                if i_bytes.endswith(b"\x06"):
                    operand = resolve_token(pe, insn.operand)
                    if isinstance(operand, dnfile.mdtable.MethodDefRow):
                        # override operand string with "address" of the method
                        method_name = self.cil_label_provider.decodeSymbolName(operand.Name.value)
                        method_addr = self.cil_label_provider.getAddress(method_name)
                        if method_addr is not None:
                            i_op_str = f"0x{method_addr:x}"
            if i_mnemonic in ["throw", "rethrow"]:
                state.setNextInstructionReachable(False)
            if i_mnemonic in ["switch"]:
                next_addrs = []
                for target in insn.operand:
                    next_addrs.append(target)
                    state.addCodeRef(i_address, target, by_jump=True)
            state.prev_opcode = i_mnemonic
            state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, i_bytes)
        state.label = self.resolveSymbol(state.start_addr)
        state.finalizeAnalysis()
        return state

    def analyzeBuffer(self, binary_info, cbAnalysisTimeout=None):
        LOGGER.debug(
            "Analyzing buffer with %d bytes @0x%08x",
            binary_info.binary_size,
            binary_info.base_addr,
        )
        self._updateLabelProviders(binary_info)
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = self.config.VERSION
        self.disassembly.setConfidenceThreshold(self.config.CONFIDENCE_THRESHOLD)
        self.disassembly.setBinaryInfo(binary_info)
        self.disassembly.binary_info.architecture = "cil"
        self.disassembly.analysis_start_ts = datetime.datetime.now(datetime.timezone.utc)
        # CIL metadata is language-neutral, but it proves that this is a
        # managed .NET/CLI module. Keep the public report contract score-only.
        self.disassembly.language = {".net": 1.0}

        LOGGER.debug("Starting parser-based analysis.")
        pe = dnfile.dnPE(data=binary_info.raw_data)
        for row in pe.net.mdtables.MethodDef:
            if not row.Rva or not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
                continue
            try:
                method_body = CilMethodBody(DnfileMethodBodyReader(pe, row))
            except Exception as exc:
                reraise_non_operational_exception(exc)
                LOGGER.error("Skipping malformed CIL method body: %s", exc)
                continue
            if not method_body.instructions:
                continue
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            self.analyzeFunction(pe, method_body.offset, method_body)
        # package up and finish
        self.disassembly.analysis_end_ts = datetime.datetime.now(datetime.timezone.utc)
        if cbAnalysisTimeout and cbAnalysisTimeout():
            self.disassembly.analysis_timeout = True
        return self.disassembly
