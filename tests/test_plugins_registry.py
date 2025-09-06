import types

import plugins


def test_run_all_isolated():
    # Arrange: register two dummy plugins, one raises
    called = {
        "good": False,
        "bad": False,
    }

    @plugins.register("good")
    def _good():
        called["good"] = True

    @plugins.register("bad")
    def _bad():
        called["bad"] = True
        raise RuntimeError("boom")

    # Act
    results = plugins.run_all(["good", "bad"])  # order preserved

    # Assert: both attempted, errors isolated
    assert called["good"] is True
    assert called["bad"] is True
    # results contain success for good and failure with message for bad
    assert ("good", True, None) in results
    bad = [r for r in results if r[0] == "bad"][0]
    assert bad[1] is False and isinstance(bad[2], str)

