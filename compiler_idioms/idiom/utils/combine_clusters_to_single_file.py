import json
import pathlib
import sys
from typing import List, Tuple

from compiler_idioms.config import DATA_DIR, TEST_DIR


def _read_parsed_pattern_from_cluster_file(cluster_file_path: pathlib.Path) -> Tuple[List, str]:
    """
    Optimization level directory contains cluster_number.json files.
    :param cluster_file_path: file that contains cluster pattern as str list, parsed pattern and
                              list of cluster members' registers, constants and original constants
    E.g.
    {
        "pattern": [
        "movsx reg_0, reg_1",
        "imul reg_0, reg_0, const_0",
        "shr reg_0, const_1",
        "add reg_2, reg_1",
        "sar reg_2, const_2",
        "sar reg_1, const_3",
        "sub reg_2, reg_1",
        "mov reg_1, reg_2"
    ],
    "parsed": [
        {
            "opcode": "movsx",
            "operands": [
                "reg_0",
                "reg_1"
            ],
            "text": "movsx reg_0, reg_1"
        },
        ....
    }
    :return: parsed pattern and name (number) of the cluster as a string
    parsed pattern example:

    """
    with cluster_file_path.open("r") as f:
        data = json.load(f)
    parsed_pattern = data.get("parsed", [])
    cluster_number_str = cluster_file_path.stem.split("_")[1]
    return parsed_pattern, cluster_number_str


def combine_clusters_of_single_optimization_level(opt_level_path: pathlib.Path, output_path: pathlib.Path):
    """
    $ tree clusters
        clusters
        ├── O0
        │   ├── cluster_0.json
        │   ├── cluster_10.json
        │   ├── cluster_11.json
        │   ├── cluster_12.json
        ...
        │   └── cluster_9.json
        ├── O1
        │   ├── cluster_10.json
        │   ├── cluster_31.json
        ...
        │   └── cluster_9.json
        ....
    For optimization level directory, accumulate parsed patters for each cluster and
    write them to single file.
    :param opt_level_path: path to given opt level in operation clusters directory
    """
    parsed_patterns_per_cluster = []
    for cluster_file in opt_level_path.glob("*"):
        parsed_pattern_info = {}
        parsed_pattern, cluster_number_str = _read_parsed_pattern_from_cluster_file(cluster_file)
        parsed_pattern_info["sequence"] = parsed_pattern
        parsed_pattern_info["cluster"] = cluster_number_str
        parsed_patterns_per_cluster.append(parsed_pattern_info)
    with (TEST_DIR / output_path).open("w") as f:
        json.dump(parsed_patterns_per_cluster, f, indent=True)


def write_all_optimizations_pro_operation(operation_name: str, operation_folder: pathlib.Path):
    for opt_level in operation_folder.glob("*"):
        combine_clusters_of_single_optimization_level(
            operation_folder / opt_level.name, pathlib.Path(f"patters-{operation_name}-{opt_level.name}.json")
        )


def main():
    divs = DATA_DIR / "divs" / "clusters"
    mods = DATA_DIR / "mods" / "clusters"
    divu = DATA_DIR / "divu" / "clusters"
    modu = DATA_DIR / "modu" / "clusters"
    write_all_optimizations_pro_operation("divs", divs)
    write_all_optimizations_pro_operation("divu", divu)
    write_all_optimizations_pro_operation("mods", mods)
    write_all_optimizations_pro_operation("modu", modu)


if __name__ == "__main__":
    sys.exit(main())
    # TODO ADD ARGUMENTS PLEASE
    # print(combine_clusters_of_single_optimization_level(DATA_DIR / 'divs' / 'clusters' / 'O0'))
    # print(combine_clusters_of_single_optimization_level(DATA_DIR / 'mods' / 'clusters' / 'O0'))
