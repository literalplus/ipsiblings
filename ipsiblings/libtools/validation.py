# validation.py
#
# (c) 2018 Marco Starke
#


def validate(condition: bool, msg: str):
    """
    Assertion style input validation
    """
    if not condition:
        raise ValueError(msg)
