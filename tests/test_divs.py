import pytest
from compiler_idioms.matcher import Matcher
from config import TEST_DIR
from icecream import ic

DIVS_TEST_FILE = TEST_DIR / "divs-10-binary"
DIVS_DATABASE = TEST_DIR / "divs-10-binary.bndb"

MODS_TEST_FILE = TEST_DIR / "dga2-newest.exe"

DIVS_100_FILE = TEST_DIR / "evaluation" / "bin" / "division"

print(DIVS_100_FILE)


@pytest.mark.skip
def test_divs_matching():
    # TODO fix this
    # probably var copy in the middle of the pattern
    matcher = Matcher()
    matches = matcher.find_idioms_in_file(str(DIVS_TEST_FILE))
    assert len(matches) >= 5
    addresses = {m.address for m in matches}
    assert 0x7C9 in addresses  # mods2 -> modulo for vars with pointers, test2 in test_loop
    assert 0x806 in addresses  # divs
    assert 0x8D2 in addresses  # divs
    assert 0xA17 in addresses  # divs
    assert 0xC3B in addresses  # divs
    assert DIVS_DATABASE.exists()


@pytest.mark.skip
def test_mods_matching():
    # TODO test if this still works (user study sample)
    # 0x40109b
    matcher = Matcher()
    matches = matcher.find_idioms_in_file(str(MODS_TEST_FILE))
    addresses = {m.address for m in matches}
    assert 0x40109B in addresses


def test_divs_2_100_gcc_opt0():
    matcher = Matcher()
    matches = matcher.find_idioms_in_file(str(DIVS_100_FILE))
    assert len(matches) >= 99
    matched_constants = {m.constant for m in matches if m.constant}
    ic(set(range(2, 101)) - matched_constants)
    assert matched_constants >= set(range(2, 101))


def test_divs_all_opts():
    matcher = Matcher()
    divs_O0_file = TEST_DIR / "evaluation" / "bin" / "test_divs_O0"
    matches = matcher.find_idioms_in_file(str(divs_O0_file))
    matched_constants = {m.constant for m in matches if m.constant}
    expected = set(range(-50, 50)) - {0, 1, -1}
    assert matched_constants >= expected
    matcher = Matcher()
    divs_O1_file = TEST_DIR / "evaluation" / "bin" / "test_divs_O1"
    matches = matcher.find_idioms_in_file(str(divs_O1_file))
    matched_constants = {m.constant for m in matches if m.constant}
    expected = set(range(-50, 50)) - {0, 1, -1}
    assert matched_constants >= expected
    matcher = Matcher()
    divs_O2_file = TEST_DIR / "evaluation" / "bin" / "test_divs_O2"
    matches = matcher.find_idioms_in_file(str(divs_O2_file))
    matched_constants = {m.constant for m in matches if m.constant}
    expected = set(range(-50, 50)) - {0, 1, -1}
    assert matched_constants >= expected
    matcher = Matcher()
    divs_O3_file = TEST_DIR / "evaluation" / "bin" / "test_divs_O3"
    matches = matcher.find_idioms_in_file(str(divs_O3_file))
    matched_constants = {m.constant for m in matches if m.constant}
    expected = set(range(-50, 50)) - {0, 1, -1}
    assert matched_constants >= expected
