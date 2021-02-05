from enum import Enum, auto
from typing import Iterable


class SiblingStatus(Enum):
    """
    Possible evaluation results for a single sibling pair.
    """

    POSITIVE = auto()
    NEGATIVE = auto()
    INDECISIVE = auto()
    CONFLICT = auto()
    ERROR = auto()

    @classmethod
    def combine(cls, statuses: Iterable['SiblingStatus']) -> 'SiblingStatus':
        overall = cls.INDECISIVE
        for status in statuses:
            transitions = _STATUS_TRANSITIONS.get(overall)
            if not transitions:
                overall = status
            else:
                next_overall = transitions.get(status)
                if next_overall:
                    overall = next_overall
        return overall


# State machine, nodes represent current overall status, edges represent a classification with that status.
# No edge means no change, None value means always override the current status
_STATUS_TRANSITIONS = {
    SiblingStatus.POSITIVE: {SiblingStatus.NEGATIVE: SiblingStatus.CONFLICT},
    SiblingStatus.NEGATIVE: {SiblingStatus.POSITIVE: SiblingStatus.CONFLICT},
    SiblingStatus.INDECISIVE: None,
    SiblingStatus.CONFLICT: {},
    SiblingStatus.ERROR: {SiblingStatus.POSITIVE: SiblingStatus.POSITIVE,
                          SiblingStatus.NEGATIVE: SiblingStatus.NEGATIVE},
}
