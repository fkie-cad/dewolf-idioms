import json
import pathlib
from typing import Dict, Tuple

from compiler_idioms.config import ROOT

MAGIC_PATH = ROOT / "idiom" / "utils" / "unsigned_magic_map.json"

DEFAULT_POWER = 32
MAX_SIGNED_INT = 2 ** 32 - 1
DEFAULT_MAX_DIVISOR = 2 ** 10


def _compute_magic_map2(max_divisor: int) -> Dict[Tuple[int, int], int]:
    """
    Combination of power and magic number is unique for each divisor.
    Here, we calculate a table for fast divisor lookup given its magic and power.
    We omit divisors that are powers of two since magic is not used for them.
    :return:
    """
    _map = {}
    for divisor in range(2, max_divisor):
        if (divisor & (divisor - 1)) != 0:
            magic, power = _get_m_p(divisor)
            _map[(magic, power)] = divisor
    return _map


def _get_m_p(d):
    nc = (MAX_SIGNED_INT + 1) / d * d - 1
    for p in range(0, 2 ** 32 + 1):
        if 2 ** p > nc * (d - 1 - (2 ** p - 1) % d):
            m = (2 ** p + d - 1 - (2 ** p - 1) % d) / d
            return (m, p)


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
            power, _ = _compute_power_with_minimal_error(divisor)
            magic = _compute_magic_number(power, divisor)
            _map[(magic, power)] = divisor
    return _map


def _compute_magic_number(power: int, divisor: int) -> int:
    y = 2 ** power
    x = divisor - 1 - ((y - 1) % divisor)
    magic = (x + y) / divisor
    return magic if magic < MAX_SIGNED_INT else magic - 2 ** 32


def _compute_power_with_minimal_error(divisor: int) -> Tuple[int, float]:
    """Compute the most appropriate power for the given divisor.
    Start from power equals default. If the error with this power is too large, increment the power till the error is small enough.
    :returns the resulting power and its error"""
    max_error = 1.0 / divisor
    power = DEFAULT_POWER
    y = 2 ** power
    x = divisor - 1 - (y - 1) % divisor
    while True:
        err = float(x * MAX_SIGNED_INT) / float(divisor * y)
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
    # print(f"Loads magic map from {MAGIC_PATH}")
    return _load_magic_map(MAGIC_PATH)


if __name__ == "__main__":
    print(compute_magic_numbers_if_not_exists(2 ** 11))
