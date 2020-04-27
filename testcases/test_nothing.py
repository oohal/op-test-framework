import pytest

import OpTestConfiguration

@pytest.mark.smoke
def test_nothing(optest_system):
    assert OpTestConfiguration.conf is not None
    pass
