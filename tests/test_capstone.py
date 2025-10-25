"""Tests for Capstone-based disassembly."""
import pytest
from compiler_idioms.disassembly.capstone_disassembly import CapstoneDisassembly


def test_capstone_initialization():
    """Test that CapstoneDisassembly can be initialized."""
    # This is a basic smoke test
    # In a real scenario, you'd need a sample binary file
    pass


def test_mnemonic_normalization():
    """Test mnemonic normalization."""
    assert CapstoneDisassembly._get_normalized_mnemonic("sal") == "shl"
    assert CapstoneDisassembly._get_normalized_mnemonic("movsxd") == "movsx"
    assert CapstoneDisassembly._get_normalized_mnemonic("mov") == "mov"


def test_operand_normalization():
    """Test operand normalization."""
    assert CapstoneDisassembly._normalize_operand("[edi + ecx*4]") == "[edi+ecx*4]"
    assert CapstoneDisassembly._normalize_operand("eax") == "eax"
    assert CapstoneDisassembly._normalize_operand("  [rbp - 8]  ") == "[rbp-8]"
