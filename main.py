import json
import pathlib
import sys
from collections import defaultdict
from typing import DefaultDict, List, Tuple

from binaryninja import Tag, TagType
from compiler_idioms.matcher import Matcher
from icecream import ic

# ic.disable()


def write_file_for_decompiler(filename, matches):
    result = {}
    for m in matches:
        result[m.address + m.length] = {
            "operation": m.operation,
            "constant": m.constant,
            "operand": m.operand,
            "start": m.address,
            "end": m.address + m.length,
        }
    with pathlib.Path(filename).open("w") as f:
        json.dump(result, f)


def main():
    matcher = Matcher()
    matches = matcher.find_idioms_in_file(sys.argv[1])
    filename = None
    if len(sys.argv) == 3:
        filename = sys.argv[2]
    # ic(sorted(matches, key=lambda x: x.constant if x.constant else 0))
    for m in sorted(matches, key=lambda x: x.constant if x.constant else 0):
        print(m)
    constants = {x.constant for x in matches if x.constant}
    # expected = set(range(2, 100))# - {76}
    # ic(expected - constants)
    # assert constants >= expected
    # if filename:
    #     write_file_for_decompiler(filename, matches)


if __name__ == "__main__":
    sys.exit(main())
