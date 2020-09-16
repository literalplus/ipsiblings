# libsiblings/construct_candidates.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#

from typing import Dict, Union, Tuple

from .. import liblog
from ..config import AppConfig
from ..model import SiblingCandidate, LowRTSiblingCandidate, Target, PreparedTargets

log = liblog.get_root_logger()


def _construct_candidates(
        targets: PreparedTargets, low_runtime=False
) -> Dict[Tuple, SiblingCandidate]:
    """
    low_runtime             use LowRTSiblingCandidate class
    """
    if not targets.targets:
        return {}
    if not targets.has_timestamps():
        log.warning('No timestamp data available trying to construct candidates')
        return {}

    candidates = {}

    for target4 in targets:
        if target4.ip_version != 4:
            continue
        for target6 in targets:
            if target6.ip_version != 6:
                continue
            candidate = _targets_to_candidate(target4, target6, low_runtime=low_runtime)
            if not candidate:
                continue
            candidates[candidate.key] = candidate
    return candidates


def _targets_to_candidate(target4: Target, target6: Target, low_runtime: bool) -> Union[SiblingCandidate, None]:
    if not target4.has_any_timestamp() or not target6.has_any_timestamp():
        return None
    if low_runtime:
        return LowRTSiblingCandidate(target4, target6)
    else:
        return SiblingCandidate(target4, target6)


def construct_candidates_for(prepared_targets: PreparedTargets, conf: AppConfig) -> Dict[Tuple, SiblingCandidate]:
    return _construct_candidates(prepared_targets, low_runtime=conf.candidates.low_runtime)
