import json
import pathlib
from typing import Dict, List

from config import DATA_DIR


def get_operation_dirs() -> List[pathlib.Path]:
    """
    Returns a list of all subdirectories which are in the same time names of operations
    """
    return [op for op in DATA_DIR.iterdir()]


def read_json_data(infile: pathlib.Path) -> Dict:
    """
    Reads json into dict
    """
    with infile.open("r") as f:
        return json.load(f)


def write_json_data(data: Dict, outfile: pathlib.Path) -> None:
    """
    Writes data dict as a json file
    """
    try:
        if not outfile.exists():
            outfile.parent.mkdir(parents=True)
    except FileExistsError:
        pass
    with outfile.open("w") as f:
        json.dump(data, f, indent=4)
