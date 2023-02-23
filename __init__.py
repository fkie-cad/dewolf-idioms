"""Main plugin file registering plugin commands in bianryninja."""
import json
import pathlib
import sys
from collections import defaultdict
from os.path import dirname, realpath
from sys import path
from threading import Lock
from typing import DefaultDict, List, Tuple

import binaryninja
from binaryninja import PluginCommand, Tag, TagType

# Add compiler idioms to the path in case it is not in the pythonpath already
current_dir = dirname(realpath(__file__))
path.append(current_dir)

from binaryninja import BinaryView, BinaryViewType
from compiler_idioms.matcher import Matcher


#
# def match(binary_view):
#     matcher = Matcher()
#     matched = matcher.find_idioms_in_file("", binary_view)
#     print(matched)
#
#
# def finalize(binary_view):
#     binary_view.store_metadata('finalized', 'yes')
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


def main(binary_view):
    matcher = Matcher()
    matches = matcher.find_idioms_in_file(binary_view.file.filename, bv=binary_view)
    # matches = matcher.find_idioms_in_file(sys.argv[1])
    filename = None
    if len(sys.argv) == 3:
        filename = sys.argv[2]
    # ic(sorted(matches, key=lambda x: x.constant if x.constant else 0))
    # for m in sorted(matches, key=lambda x: x.constant if x.constant else 0):
        # print(m)
        # for i in range(m.address, m.address+len(m.sequence)):
        #     set_tag(binary_view, tag_name=f'compiler_idiom: {m.operation}', address=i, text=f'{m.operand},{m.constant}')
        # set_tag(tag_name=f'compiler_idiom: {m.operation}', address=instr.address,
        #                     text=f'{m.operand},{m.constant}')

    # constants = {x.constant for x in matches if x.constant}
    # expected = set(range(2, 100))# - {76}
    # ic(expected - constants)
    # assert constants >= expected
    # if filename:
    #     write_file_for_decompiler(filename, matches)


TAG_SYMBOL = "⚙"


def set_tag(binary_view, tag_name: str, address: int, text: str):
    tag_type = _get_tag_type(binary_view, tag_name)
    binary_view.create_user_data_tag(address, tag_type, text, unique=True)


def read_tags(binary_view) -> DefaultDict[TagType, List[Tuple[int, Tag]]]:
    tags = defaultdict(list)
    for addr, tag in binary_view.data_tags:
        tags[tag.type].append((addr, tag))
    return tags


def _get_tag_type(binary_view, tag_type_name: str) -> TagType:
    if tag_type_name in binary_view.tag_types.keys():
        return binary_view.tag_types[tag_type_name]
    return binary_view.create_tag_type(tag_type_name, TAG_SYMBOL)


# register the plugin command
BinaryViewType.add_binaryview_initial_analysis_completion_event(main)
# PluginCommand.register_for_function(
#     "run-compiler-idioms",
#     "Compiler Idioms",
#     main
# )
