# import sys
# from collections import defaultdict
# from typing import Optional, Iterator, List, Tuple, DefaultDict
#
# from binaryninja import BinaryView, BinaryViewType, DisassemblyTextLine, TagType, Tag
#
# from compiler_idioms.disassembly.disassembly import Disassembly
# from compiler_idioms.instruction import Instruction
#
# BINJA_DATABASE_EXTENSION = 'bndb'
#
#
# class BinjaDisassembly(Disassembly):
#     TAG_SYMBOL = "⚙"
#
#     def __init__(self, path: str="", bv=None):
#         self._path = path
#         if path:
#             self._binary_view: BinaryView = self._load_binary(path)
#         else:
#
#             self._binary_view = bv
#         print(self._binary_view)
#
#     def next_disassembled_block(self) -> Iterator[List[Instruction]]:
#         """Yields next block (list of disassembled instructions) got from binja"""
#         for function in self._binary_view.functions:
#             for basic_block in function:
#                 instructions = []
#                 for assembly_line in basic_block.disassembly_text:
#                     if instr := self._convert_disassembly_line_to_instruction(
#                             assembly_line
#                     ):
#                         instructions.append(instr)
#                 yield instructions
#
#     def next_disassembly_function(self) -> Iterator[List[Instruction]]:
#         for function in self._binary_view.functions:
#             instructions = []
#             for assembly_line in function.instructions:
#                 # (['push', '    ', 'ebp'], 4198400)
#                 assembly = ' '.join([x.text for x in assembly_line[0]])
#                 address = assembly_line[1]
#                 if instr := self._convert_disassembly_tuple_to_instruction(
#                         assembly, address
#                 ):
#                     instructions.append(instr)
#             instructions = sorted(instructions, key=lambda x: x.address)
#             yield instructions
#
#     def save_database(self):
#         self._binary_view.create_database(f"{self._path}.{BINJA_DATABASE_EXTENSION}")
#
#     def set_tag(self, tag_name: str, address: int, text: str):
#         tag_type = self._get_tag_type(tag_name)
#         self._binary_view.create_user_data_tag(address, tag_type, text, unique=True)
#
#     def read_tags(self) -> DefaultDict[TagType, List[Tuple[int, Tag]]]:
#         tags = defaultdict(list)
#         for addr, tag in self._binary_view.data_tags:
#             tags[tag.type].append((addr, tag))
#         return tags
#
#     def _get_tag_type(self, tag_type_name: str) -> TagType:
#         if tag_type_name in self._binary_view.tag_types.keys():
#             return self._binary_view.tag_types[tag_type_name]
#         return self._binary_view.create_tag_type(tag_type_name, self.TAG_SYMBOL)
#
#     @staticmethod
#     def _load_binary(path: str) -> BinaryView:
#         return BinaryViewType.get_view_of_file(path)
#
#     def _convert_disassembly_line_to_instruction(self, assembly_line: DisassemblyTextLine) -> Optional[Instruction]:
#         address = assembly_line.address
#         assembly = str(assembly_line)
#         if assembly.endswith(":"):
#             return
#         if assembly.endswith("}"):
#             assembly = assembly.split("{")[:-1][0]
#         tokens = assembly.split("  ")
#         mnemonic, operands = self._get_mnemonic_with_operands(tokens)
#         return Instruction(address=address, mnemonic=mnemonic, operands=tuple(operands))
#
#     def _convert_disassembly_tuple_to_instruction(self, assembly: str, address: int) -> Optional[Instruction]:
#         if assembly.endswith(":"):
#             return
#         if assembly.endswith("}"):
#             assembly = assembly.split("{")[:-1][0]
#         tokens = assembly.split("   ")
#         mnemonic, operands = self._get_mnemonic_with_operands(tokens)
#         return Instruction(address=address, mnemonic=mnemonic, operands=tuple(operands))
#
#
#     @staticmethod
#     def _get_mnemonic_with_operands(tokens: List[str]) -> Tuple[str, List[str]]:
#         mnemonic = tokens[0].strip()
#         operands = [t for t in tokens[1:] if t != ""]
#         assert len(operands) <= 1
#         if operands:
#             operands = operands[0].strip().split(",")
#             operands = [op.strip() for op in operands]
#         return mnemonic, operands
#
#
# if __name__ == "__main__":
#     disasm = BinjaDisassembly(sys.argv[1])
#     for block in disasm.next_disassembled_block():
#         print(block)
