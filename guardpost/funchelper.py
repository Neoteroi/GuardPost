from inspect import Signature
from typing import Callable, Dict, Tuple


def args_to_dict_getter(method: Callable):
    params = list(Signature.from_callable(method).parameters)

    def args_to_dict(args: Tuple, kwargs: Dict):
        a = {}

        for index, value in enumerate(args):
            param_name = params[index]
            a[param_name] = value

        if not kwargs:
            return a

        for param_name in params:
            if param_name in kwargs:
                a[param_name] = kwargs[param_name]

        return a

    return args_to_dict
