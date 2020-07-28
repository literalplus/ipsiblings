# libsiblings/error.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#


class SiblingEvaluationError(Exception):
    def __init__(self, *args, sibling_status=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.sibling_status = sibling_status
