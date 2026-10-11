import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from test_conformance import test_payment_requirements_fixture
from test_wire import test_wire_core

test_payment_requirements_fixture()
test_wire_core()
print("python conformance: ok")
