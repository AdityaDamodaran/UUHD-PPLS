# Copyright © 2021 by University of Luxembourg.
# Developed at SnT APSIA by:
# Aditya Damodaran, aditya.damodaran@uni.lu
# Alfredo Rial, alfredo.rial@uni.lu

import sys


def get_real_size(obj, seen=None):
    size = sys.getsizeof(obj)
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)
    if isinstance(obj, dict):
        size += sum([get_real_size(v, seen) for v in obj.values()])
        size += sum([get_real_size(k, seen) for k in obj.keys()])
    elif hasattr(obj, "__dict__"):
        size += get_real_size(obj.__dict__, seen)
    elif hasattr(obj, "__iter__") and not isinstance(
        obj, (str, bytes, bytearray)
    ):
        size += sum([get_real_size(i, seen) for i in obj])
    return size
