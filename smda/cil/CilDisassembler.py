#!/usr/bin/python

import datetime
import logging
import re
from typing import TYPE_CHECKING, Any, Union, Optional

if TYPE_CHECKING:
    from dnfile import dnPE
    from dnfile.mdtable import MethodDefRow
import dnfile
from dnfile.enums import MetadataTables
from dncil.cil.body import CilMethodBody
from dncil.cil.error import MethodBodyFormatError
from dncil.clr.token import Token, StringToken, InvalidToken
from dncil.cil.body.reader import CilMethodBodyReaderBase

from smda.DisassemblyResult import DisassemblyResult
from smda.common.BinaryInfo import BinaryInfo
from smda.common.labelprovider.CilSymbolProvider import CilSymbolProvider
from .FunctionAnalysisState import FunctionAnalysisState

LOGGER = logging.getLogger(__name__)
DOTNET_META_TABLES_BY_INDEX = {table.value: table.name for table in MetadataTables}


def read_dotnet_user_string(pe, token: StringToken) -> Union[str, InvalidToken]:
    """read user string from #US stream"""
    try:
        user_string: Optional[dnfile.stream.UserString] = pe.net.user_strings.get(token.rid)
    except UnicodeDecodeError as e:
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
        return f"[{', '.join(['({:04X})'.format(x) for x in operand])}]"
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
    elif isinstance(operand, dnfile.mdtable.TypeRefRow):
        return f"{str(operand.TypeNamespace)}.{operand.TypeName}"
    elif isinstance(operand, (dnfile.mdtable.FieldRow, dnfile.mdtable.MethodDefRow)):
        return f"{operand.Name}"
    elif operand is None:
        return ""

    return str(operand)


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

    def seek(self, offset: int) -> int:
        """ """
        self.offset = offset
        return self.offset


class CilDisassembler(object):

    def __init__(self, config):
        self.config = config
        self._tfidf = None
        self.binary_info = None
        self.label_providers = []
        self.cil_label_provider = CilSymbolProvider(self.config)
        self._addLabelProviders()
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = config.VERSION

    def addPdbFile(self, binary_info, pdb_path):
        return

    def _addLabelProviders(self):
        self.label_providers.append(self.cil_label_provider)

    def _updateLabelProviders(self, binary_info):
        for provider in self.label_providers:
            provider.update(binary_info)

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
            if api_function.startswith("<dnfile.mdtable.MemberRefRow"):
                return
            self.disassembly.addr_to_api[from_addr] = api_function

    def analyzeFunction(self, pe, start_addr, method_body):
        LOGGER.debug("analyzeFunction() starting analysis of candidate @0x%08x", start_addr)
        state = FunctionAnalysisState(start_addr, method_body.instructions[0].offset, self.disassembly)
        for insn in method_body.instructions:
            state.setNextInstructionReachable(True)
            i_bytes = insn.get_bytes()
            i_address = insn.offset
            i_size = len(i_bytes)
            i_mnemonic = str(insn.opcode)
            i_op_str = format_operand(pe, insn.operand)
            # debug output for all instructions
            if False:
                from smda.cil.CilInstructionEscaper import CilInstructionEscaper
                from smda.common.SmdaInstruction import SmdaInstruction
                smda_ins = SmdaInstruction([i_address, i_bytes.hex(), i_mnemonic, i_op_str])
                escaped = CilInstructionEscaper.escapeBinary(smda_ins)
                print(
                    f"{escaped:<20}"
                    + "{:04X}".format(insn.offset)
                    + "    "
                    + f"{' '.join('{:02x}'.format(b) for b in insn.get_bytes()) : <20}"
                    + f"{str(insn.opcode) : <15}"
                    + format_operand(pe, insn.operand)
                )
            # https://en.wikipedia.org/wiki/List_of_CIL_instructions
            if i_mnemonic in ["ret"]:
                state.setNextInstructionReachable(False)
            if i_mnemonic in [
                    "beq", "beq.s", 
                    "bge", "bge.s", "bge.un", "bge.un.s",
                    "bgt", "bgt.s", "bgt.un", "bgt.un.s",
                    "ble", "ble.s", "ble.un", "ble.un.s",
                    "blt", "blt.s", "blt.un", "blt.un.s",
                    "bne.un", "bne.un.s", 
                    "br", "br.s", 
                    "brfalse", "brfalse.s", 
                    "brinst", "brinst.s", 
                    "brnull", "brnull.s", 
                    "brtrue", "brtrue.s", 
                    "brzero", "brzero.s"]:
                target = int(i_op_str, 16)
                state.addCodeRef(i_address, target, by_jump=True)
            if i_mnemonic in ["jmp"]:
                raise Exception("Found unhandled CIL jmp instruction, report back its structure and have Daniel fix it.")
                target = int(i_op_str, 16)
                state.addCodeRef(i_address, target, by_jump=True)
                state.setNextInstructionReachable(False)
            if i_mnemonic in ["ldstr"]:
                # we possibly want to extract and collect these and put them in the stringref part of SmdaFunction
                self.disassembly.addStringRef(start_addr, i_address, i_op_str[1:-1])
            if i_mnemonic in ["call", "callvirt"]:
                self._updateApiInformation(i_address, i_bytes, i_op_str)
                # https://blog.objektkultur.de/about-tail-recursion-in-.net/
                if state.prev_opcode.startswith("tail"):
                    state.setNextInstructionReachable(False)
                if i_bytes.endswith(b"\x06"):
                    operand = resolve_token(pe, insn.operand)
                    if isinstance(operand, dnfile.mdtable.MethodDefRow):
                        # override operand string with "address" of the method
                        method_name = self.cil_label_provider.decodeSymbolName(operand.Name.value)
                        i_op = f"0x{self.cil_label_provider.getAddress(method_name):x}"
            if i_mnemonic in ["throw"]:
                state.setNextInstructionReachable(False)
            if i_mnemonic in ["switch"]:
                next_addrs = []
                for target in insn.operand:
                    next_addrs.append(target)
                    state.addCodeRef(i_address, target, by_jump=True)
            state.prev_opcode = i_mnemonic
            state.addInstruction(i_address, i_size, i_mnemonic, i_op_str, i_bytes)
        state.label = self.resolveSymbol(state.start_addr)
        analysis_result = state.finalizeAnalysis()
        return state

    def analyzeBuffer(self, binary_info, cbAnalysisTimeout=None):
        LOGGER.debug("Analyzing buffer with %d bytes @0x%08x", binary_info.binary_size, binary_info.base_addr)
        self._updateLabelProviders(binary_info)
        self.disassembly = DisassemblyResult()
        self.disassembly.smda_version = self.config.VERSION
        self.disassembly.setBinaryInfo(binary_info)
        self.disassembly.binary_info.architecture = "cil"
        self.disassembly.analysis_start_ts = datetime.datetime.now(datetime.timezone.utc)
        self.disassembly.language = "cil"

        LOGGER.debug("Starting parser-based analysis.")
        pe = dnfile.dnPE(data=binary_info.raw_data)
        all_instruction_offsets = set([])
        for row in pe.net.mdtables.MethodDef:
            if not row.ImplFlags.miIL or any((row.Flags.mdAbstract, row.Flags.mdPinvokeImpl)):
                # skip methods that do not have a method body
                continue
            try:
                method_body = CilMethodBody(DnfileMethodBodyReader(pe, row))
            except MethodBodyFormatError as e:
                LOGGER.error(e)
                continue
            if not method_body.instructions:
                continue
            if cbAnalysisTimeout and cbAnalysisTimeout():
                break
            function_result_state = self.analyzeFunction(pe, method_body.offset, method_body)
        # package up and finish
        self.disassembly.analysis_end_ts = datetime.datetime.now(datetime.timezone.utc)
        if cbAnalysisTimeout():
            self.disassembly.analysis_timeout = True
        return self.disassembly
