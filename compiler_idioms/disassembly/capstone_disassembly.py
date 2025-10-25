import pathlib
from typing import Optional

import capstone
import lief

from compiler_idioms.disassembly.disassembly import Disassembly
from compiler_idioms.instruction import Instruction

MNEMONICS_TO_CONSIDER = {"movsxd": "movsx"}


class CapstoneDisassembly(Disassembly):
    """
    Class that generates assembly using Capstone disassembler.
    Supports multiple architectures including ARM.
    """

    def __init__(self, path, buffer=None):
        self.binary = lief.parse(path) if not buffer else None
        self.path = path
        self.buffer = buffer
        self.md = self._initialize_capstone()
        self.functions = self._extract_functions()

    def _initialize_capstone(self) -> capstone.Cs:
        """Initialize capstone disassembler based on binary architecture."""
        if self.binary:
            # Get architecture based on binary format
            try:
                if isinstance(self.binary, lief.ELF.Binary):
                    arch = self.binary.header.machine_type
                elif isinstance(self.binary, lief.MachO.Binary):
                    # For Mach-O, get CPU type from header
                    arch = self.binary.header.cpu_type
                elif isinstance(self.binary, lief.PE.Binary):
                    arch = self.binary.header.machine
                else:
                    # Fallback: try abstract interface
                    arch = getattr(self.binary.abstract.header, 'machine_type', None)
                    if arch is None:
                        # Default to ARM64 for unknown Mach-O binaries (common on macOS)
                        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                        md.detail = True
                        return md
            except AttributeError:
                # If we can't determine architecture, default to ARM64 (macOS)
                md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                md.detail = True
                return md
            
            # Map architecture to Capstone
            if isinstance(self.binary, lief.ELF.Binary):
                if arch == lief.ELF.ARCH.ARM:
                    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
                elif arch == lief.ELF.ARCH.AARCH64:
                    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                elif arch == lief.ELF.ARCH.x86_64:
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                elif arch == lief.ELF.ARCH.i386:
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                else:
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            elif isinstance(self.binary, lief.MachO.Binary):
                if arch == lief.MachO.CPU_TYPES.ARM64:
                    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                elif arch == lief.MachO.CPU_TYPES.ARM:
                    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
                elif arch == lief.MachO.CPU_TYPES.x86_64:
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                elif arch == lief.MachO.CPU_TYPES.x86:
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                else:
                    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            elif isinstance(self.binary, lief.PE.Binary):
                if arch == lief.PE.MACHINE_TYPES.AMD64:
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                elif arch == lief.PE.MACHINE_TYPES.I386:
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                elif arch == lief.PE.MACHINE_TYPES.ARM64:
                    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                elif arch == lief.PE.MACHINE_TYPES.ARM:
                    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
                else:
                    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                # Default
                md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            # Default when using buffer
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        
        md.detail = True
        return md

    def _extract_functions(self):
        """Extract functions from the binary."""
        functions = []
        if self.binary:
            # Try to get functions from symbols
            for symbol in self.binary.abstract.symbols:
                if symbol.value and symbol.size > 0:
                    functions.append((symbol.value, symbol.size, symbol.name))
        return functions

    def next_disassembly_function(self):
        """Generates a disassembly block as a list of Instruction-s"""
        if not self.binary:
            return

        for func_addr, func_size, func_name in self.functions:
            # Get the section containing this function
            section = self._get_section_for_address(func_addr)
            if not section:
                continue

            # Calculate offset within section
            section_offset = func_addr - section.virtual_address
            code = bytes(section.content[section_offset:section_offset + func_size])

            assembly_lines = []
            for instruction in self.md.disasm(code, func_addr):
                instr = self._convert_to_instruction(instruction)
                if instr:
                    assembly_lines.append(instr)
            
            if assembly_lines:
                yield assembly_lines

    def get_function_at(self, address):
        """Get disassembled instructions for function at specific address."""
        if not self.binary:
            return []

        # Find function containing this address
        func_info = None
        for func_addr, func_size, func_name in self.functions:
            if func_addr <= address < func_addr + func_size:
                func_info = (func_addr, func_size, func_name)
                break

        if not func_info:
            # Try to disassemble a reasonable amount of code from this address
            func_addr = address
            func_size = 1024  # Default size if function bounds unknown

        section = self._get_section_for_address(func_addr)
        if not section:
            return []

        section_offset = func_addr - section.virtual_address
        code = bytes(section.content[section_offset:section_offset + func_size])

        assembly_lines = []
        for instruction in self.md.disasm(code, func_addr):
            instr = self._convert_to_instruction(instruction)
            if instr:
                assembly_lines.append(instr)
        
        return assembly_lines

    def _get_section_for_address(self, address):
        """Get the section containing the given address."""
        if not self.binary:
            return None
        
        for section in self.binary.abstract.sections:
            if section.virtual_address <= address < section.virtual_address + section.size:
                return section
        return None

    def _convert_to_instruction(self, cs_insn) -> Optional[Instruction]:
        """Convert capstone instruction to our Instruction format."""
        mnemonic = cs_insn.mnemonic
        
        # Parse operands
        op_str = cs_insn.op_str.strip()
        if op_str:
            operands = [self._normalize_operand(op.strip()) for op in op_str.split(",")]
        else:
            operands = []

        # Filter out jump instructions' target operands
        if mnemonic in {"jns", "js", "jmp", "je", "jne", "ja", "jb", "jae", "jbe", "jge", "jle",
                        "b", "beq", "bne", "blt", "ble", "bgt", "bge"}:  # Include ARM branches
            operands = []

        return Instruction(
            cs_insn.address,
            self._get_normalized_mnemonic(mnemonic),
            tuple(operands),
            matched=False
        )

    @staticmethod
    def _normalize_operand(operand: str) -> str:
        """Normalize operand format to match SMDA style."""
        operand = operand.strip()
        # Remove spaces in memory operands like [edi + ecx*4] -> [edi+ecx*4]
        if operand.startswith("[") or operand.startswith("("):
            return operand.replace(" ", "")
        return operand

    @staticmethod
    def _get_normalized_mnemonic(mnemonic: str) -> str:
        """
        Normalize mnemonics to match pattern expectations.
        Some mnemonics differ between disassemblers.
        """
        if mnemonic in MNEMONICS_TO_CONSIDER:
            return MNEMONICS_TO_CONSIDER[mnemonic]
        if mnemonic == "sal":
            return "shl"
        return mnemonic
