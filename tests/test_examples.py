import glob
import importlib
import sys
from pathlib import Path

import pytest

examples = [
    file for file in glob.glob("./examples/*.py") if not file.endswith("__init__.py")
]


sys.path.append("./examples")


@pytest.mark.parametrize("file_path", examples)
def test_example(file_path: str):
    module_name = Path(file_path).stem
    # assertions are in the imported code
    importlib.import_module(module_name)
