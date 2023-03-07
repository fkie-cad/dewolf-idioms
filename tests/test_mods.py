from compiler_idioms.matcher import Matcher
from compiler_idioms.config import TEST_DIR

DIVS_TEST_FILE = TEST_DIR / "divs-10-binary"
DIVS_DATABASE = TEST_DIR / "divs-10-binary.bndb"

MODS_TEST_FILE = TEST_DIR / "dga2-newest.exe"

DIVS_100_FILE = TEST_DIR / "evaluation" / "bin" / "modulo_signed_0_100_O0"

print(DIVS_100_FILE)


# def test_divs_matching():
#     matcher = Matcher()
#     matches = matcher.find_idioms_in_file(str(DIVS_TEST_FILE))
#     assert len(matches) >= 5
#     addresses = {m.address for m in matches}
#     assert 0x7c9 in addresses  # mods2 -> modulo for vars with pointers, test2 in test_loop
#     assert 0x806 in addresses  # divs
#     assert 0x8D2 in addresses  # divs
#     assert 0xA17 in addresses  # divs
#     assert 0xC3B in addresses  # divs
#     assert DIVS_DATABASE.exists()

#
# def test_mods_matching():
#     # 0x40109b
#     matcher = Matcher()
#     matches = matcher.find_idioms_in_file(str(MODS_TEST_FILE))
#     addresses = {m.address for m in matches}
#     assert 0x40109b in addresses


def test_mods_2_100_gcc_O0():
    matcher = Matcher()
    matches = matcher.find_idioms_in_file(str(DIVS_100_FILE))
    assert len(matches) >= 99
    matched_constants = {m.constant for m in matches if m.constant}
    print(set(range(2, 101)) - matched_constants)
    assert matched_constants >= set(range(2, 101))


def test_mods_all_opts():
    matcher = Matcher()
    mods_O0_file = TEST_DIR / "evaluation" / "bin" / "test_mods_O0"
    matches = matcher.find_idioms_in_file(str(mods_O0_file))
    matched_constants = sorted([m.constant for m in matches if m.constant])
    expected = sorted(list(range(2, 50)) + list(range(2, 50)) + [50])
    assert matched_constants[1:] == expected
    matcher = Matcher()
    mods_O1_file = TEST_DIR / "evaluation" / "bin" / "test_mods_O1"
    matches = matcher.find_idioms_in_file(str(mods_O1_file))
    matched_constants = sorted([m.constant for m in matches if m.constant])
    expected = sorted(list(range(2, 50)) + list(range(2, 50)) + [50])
    assert matched_constants[1:] == expected
    matcher = Matcher()
    mods_O2_file = TEST_DIR / "evaluation" / "bin" / "test_mods_O2"
    matches = matcher.find_idioms_in_file(str(mods_O2_file))
    matched_constants = sorted([m.constant for m in matches if m.constant])
    expected = sorted(list(range(2, 50)) + list(range(2, 50)) + [50])
    assert matched_constants[1:] == expected
    matcher = Matcher()
    mods_O3_file = TEST_DIR / "evaluation" / "bin" / "test_mods_O3"
    matches = matcher.find_idioms_in_file(str(mods_O3_file))
    matched_constants = sorted([m.constant for m in matches if m.constant])
    expected = sorted(list(range(2, 50)) + list(range(2, 50)) + [50])
    assert matched_constants[1:] == expected
