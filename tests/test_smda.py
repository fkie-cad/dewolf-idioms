import pytest
from compiler_idioms.anonymization import anonymize_instruction, anonymize_instructions_smda
from compiler_idioms.instruction import Instruction


class TestSmdaAnonymization:
    @pytest.mark.parametrize(
        "input, output",
        [
            (Instruction(1, "lea", ("ecx", "[rax*4]")), Instruction(1, "lea", ("reg_0", "[reg_1*const_0]"))),
            (Instruction(1, "lea", ("ecx", "[edx+rax*4+8]")), Instruction(1, "lea", ("reg_0", "[reg_1+reg_2*const_0+const_1]"))),
            (Instruction(1, "lea", ("ecx", "[edx+rax*4+4]")), Instruction(1, "lea", ("reg_0", "[reg_1+reg_2*const_0+const_0]"))),
            (Instruction(2, "add", ("rax", "rax")), Instruction(2, "add", ("reg_0", "reg_0"))),
            (Instruction(3, "retn", ("",)), Instruction(3, "retn", ())),
            (Instruction(3, "cdq", ()), Instruction(3, "cdq", ())),
            # TODO dword ptr as erroneously const
            # (Instruction(address=2009, mnemonic='call', operands=('qword ptr [r12 + rbx*8]',),()),
            # Instruction(address=1992, mnemonic='nop', operands=('dword ptr [rax + rax]',)
            # Instruction(address=1584, mnemonic='lea', operands=('rdi', '[rip + 0x2009d9]')
            # # movsx   eax, BYTE PTR [edx+4] - x86 msvc
        ],
    )
    def test_single_instruction_anonymization(self, input, output):
        anonymized = anonymize_instruction(input)
        # ic(anonymized)
        assert anonymized == output

    @pytest.mark.parametrize(
        "input, output",
        [
            (Instruction(1, "mov", ("eax", "dword ptr [ebp-4]")), Instruction(1, "mov", ("reg_0", "loc0"))),
            (Instruction(1, "mov", ("eax", "dword ptr [rbp-0xc]")), Instruction(1, "mov", ("reg_0", "loc0"))),
            (Instruction(2, "mov", ("eax", "dword ptr [rbp+0xc]")), Instruction(2, "mov", ("reg_0", "loc0"))),
            (Instruction(3, "mov", ("eax", "dword ptr [ebp+0xc]")), Instruction(3, "mov", ("reg_0", "loc0"))),
            (Instruction(3, "mov", ("byte ptr [esp]", "eax")), Instruction(3, "mov", ("loc0", "reg_0")))
            # TODO dword ptr as erroneously const
            # mov     eax, DWORD PTR _arr$[ebp]
            # mov     QWORD PTR [rsp+8], rcx
            # lea     eax, DWORD PTR c$[rsp]
            # eax, dword ptr [rbp - 0x14]
        ],
    )
    def test_single_instruction_with_variables_anonymization(self, input, output):
        anonymized = anonymize_instruction(input)
        # ic(anonymized)
        assert anonymized == output

    def test_instruction_sequence_anonymization(self):
        # combination of locations and lea
        instructions = [
            Instruction(1782, "mov", ("edx", "dword ptr [rbp-0x14]")),
            Instruction(1785, "movsx", ("rax", "edx")),
            Instruction(1788, "imul", ("rax", "rax", "0x51eb851f")),
            Instruction(1795, "shr", ("rax", "0x20")),
            Instruction(1799, "mov", ("ecx", "eax")),
            Instruction(1801, "sar", ("ecx", "3")),
            Instruction(1804, "mov", ("eax", "edx")),
            Instruction(1806, "sar", ("eax", "0x1f")),
            Instruction(1809, "sub", ("ecx", "eax")),
            Instruction(1811, "mov", ("eax", "ecx")),
            Instruction(1813, "sal", ("eax", "2")),
            Instruction(1816, "add", ("eax", "ecx")),
            Instruction(1818, "lea", ("ecx", "[rax*4]")),
            Instruction(1825, "add", ("eax", "ecx")),
            Instruction(1827, "sub", ("edx", "eax")),
            Instruction(1829, "mov", ("eax", "edx")),
            Instruction(1831, "mov", ("dword ptr [rbp - 4]", "eax")),
        ]
        anonymized = [
            Instruction(1782, "mov", ("reg_0", "loc0")),
            Instruction(1785, "movsx", ("reg_1", "reg_0")),
            Instruction(1788, "imul", ("reg_1", "reg_1", "const_0")),
            Instruction(1795, "shr", ("reg_1", "const_1")),
            Instruction(1799, "mov", ("reg_2", "reg_3")),
            Instruction(1801, "sar", ("reg_2", "const_2")),
            Instruction(1804, "mov", ("reg_3", "reg_0")),
            Instruction(1806, "sar", ("reg_3", "const_3")),
            Instruction(1809, "sub", ("reg_2", "reg_3")),
            Instruction(1811, "mov", ("reg_3", "reg_2")),
            Instruction(1813, "sal", ("reg_3", "const_4")),
            Instruction(1816, "add", ("reg_3", "reg_2")),
            Instruction(1818, "lea", ("reg_2", "[reg_1*const_5]")),
            Instruction(1825, "add", ("reg_3", "reg_2")),
            Instruction(1827, "sub", ("reg_0", "reg_3")),
            Instruction(1829, "mov", ("reg_3", "reg_0")),
            Instruction(1831, "mov", ("loc1", "reg_3")),
        ]

        original_registers = {
            "reg_0": "edx",
            "reg_1": "rax",
            "reg_2": "ecx",
            "reg_3": "eax",
        }
        original_constants = {"const_0": "0x51eb851f", "const_1": "0x20", "const_2": "3", "const_3": "0x1f", "const_4": "2", "const_5": "4"}
        original_locations = {"loc0": "dword ptr [rbp - 0x14]", "loc1": "dword ptr [rbp - 4]"}
        anonym, orig_const, orig_reg = anonymize_instructions_smda(instructions)

        assert anonym == anonymized
        assert orig_const == original_constants
        assert orig_reg == original_registers

    def test_mods_11(self):
        # here one const (const_2) occurs twice
        instr = [
            Instruction(address=1727, mnemonic="movsx", operands=("rax", "edx"), matched=False),
            Instruction(address=1730, mnemonic="imul", operands=("rax", "rax", "0x4ec4ec4f"), matched=False),
            Instruction(address=1737, mnemonic="shr", operands=("rax", "0x20"), matched=False),
            Instruction(address=1741, mnemonic="mov", operands=("ecx", "eax"), matched=False),
            Instruction(address=1743, mnemonic="sar", operands=("ecx", "2"), matched=False),
            Instruction(address=1746, mnemonic="mov", operands=("eax", "edx"), matched=False),
            Instruction(address=1748, mnemonic="sar", operands=("eax", "0x1f"), matched=False),
            Instruction(address=1751, mnemonic="sub", operands=("ecx", "eax"), matched=False),
            Instruction(address=1753, mnemonic="mov", operands=("eax", "ecx"), matched=False),
            Instruction(address=1755, mnemonic="add", operands=("eax", "eax"), matched=False),
            Instruction(address=1757, mnemonic="add", operands=("eax", "ecx"), matched=False),
            Instruction(address=1759, mnemonic="sal", operands=("eax", "2"), matched=False),
            Instruction(address=1762, mnemonic="add", operands=("eax", "ecx"), matched=False),
            Instruction(address=1764, mnemonic="sub", operands=("edx", "eax"), matched=False),
            Instruction(address=1766, mnemonic="mov", operands=("eax", "edx"), matched=False),
            Instruction(address=1768, mnemonic="mov", operands=("dword ptr [rbp - 4]", "eax"), matched=False),
        ]
        anonymized = [
            Instruction(address=1727, mnemonic="movsx", operands=("reg_0", "reg_1"), matched=False),
            Instruction(address=1730, mnemonic="imul", operands=("reg_0", "reg_0", "const_0"), matched=False),
            Instruction(address=1737, mnemonic="shr", operands=("reg_0", "const_1"), matched=False),
            Instruction(address=1741, mnemonic="mov", operands=("reg_2", "reg_3"), matched=False),
            Instruction(address=1743, mnemonic="sar", operands=("reg_2", "const_2"), matched=False),
            Instruction(address=1746, mnemonic="mov", operands=("reg_3", "reg_1"), matched=False),
            Instruction(address=1748, mnemonic="sar", operands=("reg_3", "const_3"), matched=False),
            Instruction(address=1751, mnemonic="sub", operands=("reg_2", "reg_3"), matched=False),
            Instruction(address=1753, mnemonic="mov", operands=("reg_3", "reg_2"), matched=False),
            Instruction(address=1755, mnemonic="add", operands=("reg_3", "reg_3"), matched=False),
            Instruction(address=1757, mnemonic="add", operands=("reg_3", "reg_2"), matched=False),
            Instruction(address=1759, mnemonic="sal", operands=("reg_3", "const_2"), matched=False),
            Instruction(address=1762, mnemonic="add", operands=("reg_3", "reg_2"), matched=False),
            Instruction(address=1764, mnemonic="sub", operands=("reg_1", "reg_3"), matched=False),
            Instruction(address=1766, mnemonic="mov", operands=("reg_3", "reg_1"), matched=False),
            Instruction(address=1768, mnemonic="mov", operands=("loc0", "reg_3"), matched=False),
        ]
        res, _, _ = anonymize_instructions_smda(instr)
        assert anonymized == res


@pytest.mark.skip
class TestSmdaDisassembly:
    def test_relative_jumps(self):
        pass

    def test_shifts_replacement(self):
        pass

    def test_type_info(self):
        # [rip +?
        # or something with qword ptr [...]?
        # should we convert qword -> QWORD?
        pass

    def test_type_info_lowercase_uppercase(self):
        pass
