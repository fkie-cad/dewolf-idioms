import ctypes
import json
import pathlib
from typing import Dict, Tuple

from compiler_idioms.config import ROOT

MAGIC_PATH = ROOT / "idiom" / "utils" / "magic_map_long.json"

DEFAULT_POWER = 64
MAX_SIGNED_INT = 2 ** 63 - 1
DEFAULT_MAX_DIVISOR = 2 ** 14


def _compute_magic_map(max_divisor: int) -> Dict[Tuple[int, int], int]:
    """
    Combination of power and magic number is unique for each divisor.
    Here, we calculate a table for fast divisor lookup given its magic and power.
    We omit divisors that are powers of two since magic is not used for them.
    :return:
    """
    _map = {}
    for divisor in range(2, max_divisor):
        if (divisor & (divisor - 1)) != 0:
            # magic, power = _get_m_p(divisor)
            power, _ = _compute_power_with_minimal_error(divisor)
            magic = _compute_magic_number(power, divisor)
            _map[(magic, power)] = divisor
            if divisor == 10:
                print(magic, power, hex(int(magic)))
            if ctypes.c_int32(int(magic)).value > 0:
                _map[(-magic, power)] = -divisor
            else:
                _map[(-ctypes.c_int32(int(magic)).value, power)] = -divisor
    return _map


def _compute_magic_number(power: int, divisor: int) -> int:
    return (pow(2, power) + divisor - pow(2, power, divisor)) // divisor

    y = 2 ** power
    x = divisor - y % divisor
    magic = (x + y) / divisor
    return magic


def _compute_power_with_minimal_error(divisor: int) -> Tuple[int, float]:
    """Compute the most appropriate power for the given divisor.
    Start from power equals default. If the error with this power is too large, increment the power till the error is small enough.
    :returns the resulting power and its error"""
    max_error = 1.0 / divisor
    power = DEFAULT_POWER
    y = 2 ** power
    x = divisor - y % divisor
    while True:
        err = float((x * MAX_SIGNED_INT)) / float(divisor * y)
        if err < max_error:
            error = err
            break
        power += 1
        y = 2 ** power
        x = divisor - y % divisor
    return power, error


def _dump_magic_map(magic_map: Dict[Tuple[int, int], int], path: pathlib.Path) -> None:
    """Wir save reverted map to file for serialization simplicity sake: each (magic, pow) : div is unique,
    so we just swap them and use div as a json dict key"""
    with path.open("w") as f:
        reverted_magic_map = {value: key for key, value in magic_map.items()}
        json.dump(reverted_magic_map, f)


def _load_magic_map(path: pathlib.Path):
    """On loading, we need to change from div_str: [magic, pow] to (magic, pow) : div"""
    with path.open("r") as f:
        reverted_magic_map = json.load(f)
    magic_map = {}
    for divisor_str, magic_tuple_list in reverted_magic_map.items():
        magic_map[tuple(magic_tuple_list)] = int(divisor_str)
    return magic_map


def compute_magic_numbers_if_not_exists(max_divisor=DEFAULT_MAX_DIVISOR):
    if max_divisor > DEFAULT_MAX_DIVISOR or not MAGIC_PATH.exists():
        print(f"Computes magic map from {2} to {max_divisor}")
        magic_map = _compute_magic_map(max_divisor)
        _dump_magic_map(magic_map, MAGIC_PATH)
        return magic_map
    print(f"Loads magic map from {MAGIC_PATH}")
    return _load_magic_map(MAGIC_PATH)


if __name__ == "__main__":
    compute_magic_numbers_if_not_exists(2 ** 14)
    # print(compute_magic_numbers_if_not_exists(2 ** 11))
