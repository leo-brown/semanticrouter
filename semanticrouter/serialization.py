"""Strict JSON hydration for the public, vendor-neutral model.

Dataclasses only; never evaluates expressions or instantiates caller-named classes.
"""
from dataclasses import fields, is_dataclass
from types import UnionType
from typing import Union, get_args, get_origin, get_type_hints
from .model import Router


def _decode(kind, value, path):
    origin = get_origin(kind)
    args = get_args(kind)
    if origin in (Union, UnionType):
        for alternative in args:
            try:
                return _decode(alternative, value, path)
            except ValueError:
                pass
        raise ValueError(f'{path}: value does not match the model type')
    if kind is type(None):
        if value is not None:
            raise ValueError(f'{path}: expected null')
        return None
    if origin is list:
        if not isinstance(value, list):
            raise ValueError(f'{path}: expected an array')
        return [_decode(args[0], item, f'{path}[{index}]') for index, item in enumerate(value)]
    if origin is dict:
        if not isinstance(value, dict):
            raise ValueError(f'{path}: expected an object')
        return {_decode(args[0], key, path): _decode(args[1], item, f'{path}.{key}') for key, item in value.items()}
    if is_dataclass(kind):
        if not isinstance(value, dict):
            raise ValueError(f'{path}: expected an object')
        names = {f.name for f in fields(kind)}
        unknown = set(value) - names
        if unknown:
            raise ValueError(f'{path}: unknown fields: {", ".join(sorted(unknown))}')
        hints = get_type_hints(kind)
        decoded = {key: _decode(hints[key], item, f'{path}.{key}') for key, item in value.items()}
        try:
            return kind(**decoded)
        except TypeError as exc:
            raise ValueError(f'{path}: missing required fields') from exc
    if type(value) is not kind:
        raise ValueError(f'{path}: expected {kind.__name__}')
    return value


def router_from_dict(value):
    return _decode(Router, value, 'router')
