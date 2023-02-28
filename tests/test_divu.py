from compiler_idioms.matcher import Matcher
from compiler_idioms.config import TEST_DIR
from icecream import ic

DIVS_TEST_FILE = TEST_DIR / "divs-10-binary"
DIVS_DATABASE = TEST_DIR / "divs-10-binary.bndb"

MODS_TEST_FILE = TEST_DIR / "dga2-newest.exe"

DIVS_100_FILE = TEST_DIR / "evaluation" / "bin" / "division"


def test_divs_all_opts():
    matcher = Matcher()
    divu_O0_file = TEST_DIR / "evaluation" / "bin" / "test_divu_O0"
    matches = matcher.find_idioms_in_file(str(divu_O0_file))
    matched_constants = {m.constant for m in matches if m.constant}
    expected = set(range(2, 100))
    ic(expected - matched_constants)
    assert matched_constants >= expected
    matcher = Matcher()
    divu_O1_file = TEST_DIR / "evaluation" / "bin" / "test_divu_O1"
    matches = matcher.find_idioms_in_file(str(divu_O1_file))
    matched_constants = {m.constant for m in matches if m.constant}
    expected = set(range(2, 100))
    ic(expected - matched_constants)
    assert matched_constants >= expected
    matcher = Matcher()
    divu_O2_file = TEST_DIR / "evaluation" / "bin" / "test_divu_O2"
    matches = matcher.find_idioms_in_file(str(divu_O2_file))
    matched_constants = {m.constant for m in matches if m.constant}
    expected = set(range(2, 100))
    ic(expected - matched_constants)
    assert matched_constants >= expected
    divu_O3_file = TEST_DIR / "evaluation" / "bin" / "test_divu_O3"
    matches = matcher.find_idioms_in_file(str(divu_O3_file))
    matched_constants = {m.constant for m in matches if m.constant}
    expected = set(range(2, 100))
    ic(expected - matched_constants)
    assert matched_constants >= expected
