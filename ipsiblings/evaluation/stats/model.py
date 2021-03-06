from collections import defaultdict
from typing import Dict, Tuple, List, Set, Optional

from ..model import SiblingStatus
from ...model.const import EvaluatorChoice


class AlgorithmPosNegMetrics:
    def __init__(self):
        # true status -> count
        # e.g. for positives: POSITIVE -> 10 would mean 10 true positives
        self.true_values: Dict[SiblingStatus, int] = defaultdict(lambda: 0)
        self.probables = 0
        self.improbables = 0


class AlgorithmMetrics:
    def __init__(self):
        self.posneg: Dict[bool, AlgorithmPosNegMetrics] = defaultdict(lambda: AlgorithmPosNegMetrics())
        self.conflicts = 0
        self.indecisives = 0
        self.errors = 0

    def add(
            self,
            my_status: SiblingStatus, true_status: SiblingStatus,
            is_probable: bool, is_improbable: bool
    ):
        no_definite_decision = true_status not in {SiblingStatus.POSITIVE, SiblingStatus.NEGATIVE}
        if my_status == SiblingStatus.POSITIVE or my_status == SiblingStatus.NEGATIVE:
            is_positive = my_status == SiblingStatus.POSITIVE
            metrics = self.posneg[is_positive]
            metrics.true_values[true_status] += 1
            if no_definite_decision:
                if is_probable and not is_improbable:
                    metrics.probables += 1
                elif is_improbable and not is_probable:
                    metrics.improbables += 1
        elif my_status == SiblingStatus.CONFLICT:
            self.conflicts += 1
        elif my_status == SiblingStatus.INDECISIVE:
            self.indecisives += 1
        elif my_status == SiblingStatus.ERROR:
            self.errors += 1


class PeerStats:
    def __init__(self):
        self.v4_decisions: Dict[str, Dict[str, SiblingStatus]] = defaultdict(lambda: dict())
        self.v6_decisions: Dict[str, Dict[str, SiblingStatus]] = defaultdict(lambda: dict())
        self.v4_dupecount: Dict[str, int] = defaultdict(lambda: 0)
        self.v6_dupecount: Dict[str, int] = defaultdict(lambda: 0)

    def record(self, ip4: str, ip6: str, group_results: Dict[str, SiblingStatus]):
        for group, decision in group_results.items():
            self._update_decisions(decision, group, self.v4_decisions[ip4])
            self._update_decisions(decision, group, self.v6_decisions[ip6])
            if decision == SiblingStatus.POSITIVE and group == "starke":
                self.v4_dupecount[ip4] += 1
                self.v6_dupecount[ip6] += 1

    def _update_decisions(self, decision: SiblingStatus, group: str, existing_statuses: Dict[str, SiblingStatus]):
        existing = existing_statuses.get(group, SiblingStatus.INDECISIVE)
        if existing == SiblingStatus.CONFLICT or (
                existing != SiblingStatus.INDECISIVE and decision in [SiblingStatus.INDECISIVE, SiblingStatus.ERROR]
        ):
            return
        elif existing == SiblingStatus.POSITIVE and decision == SiblingStatus.NEGATIVE:
            existing_statuses[group] = SiblingStatus.CONFLICT
        elif existing == SiblingStatus.NEGATIVE and decision == SiblingStatus.POSITIVE:
            existing_statuses[group] = SiblingStatus.CONFLICT
        else:
            existing_statuses[group] = decision


class CrossStats:
    _METRIC_GROUPS: Dict[str, Set[EvaluatorChoice]] = {
        # metrics which, if they yield a result, will almost always yield the true status.
        'definite': {
            EvaluatorChoice.TCP_OPTIONS,  # negative only if mismatch, a strong indicator
            EvaluatorChoice.SSH_KEYSCAN,  # only yields if both show keys, and a match/mismatch is a strong indicator
            EvaluatorChoice.BITCOIN_ADDR,  # negative only if timestamps cannot come from same node
            EvaluatorChoice.BITCOIN,  # negative only if proto + user agent + services consistent & mismatch
        },
        'most_definite': {
            EvaluatorChoice.TCP_OPTIONS,  # negative only if mismatch, a strong indicator
            EvaluatorChoice.SSH_KEYSCAN,  # only yields if both show keys, and a match/mismatch is a strong indicator
        },
        'btc_definite': {
            EvaluatorChoice.BITCOIN_ADDR,  # negative only if timestamps cannot come from same node
            EvaluatorChoice.BITCOIN,  # negative only if proto + user agent + services consistent & mismatch
        },
        # validating metrics which will usually yield a correct classification
        'probable': {EvaluatorChoice.DOMAIN},
        # falsifying metrics which will usually yield a correct classification
        'improbable': {EvaluatorChoice.BITCOIN_ADDR_SVC},
        'starke': {EvaluatorChoice.TCPRAW_STARKE, EvaluatorChoice.ML_STARKE},
        'scheitle': {EvaluatorChoice.TCPRAW_SCHEITLE},
        'keyscan': {EvaluatorChoice.SSH_KEYSCAN},
    }

    @classmethod
    def get_group_names(cls):
        return cls._METRIC_GROUPS.keys()

    def __init__(self):
        self.metrics: Dict[str, AlgorithmMetrics] = defaultdict(AlgorithmMetrics)
        self.peer_stats = PeerStats()

    def add(self, ip4: str, ip6: str, evaluator_results: Dict[EvaluatorChoice, SiblingStatus]):
        group_results: Dict[str, SiblingStatus] = {
            key: self._combine(evaluator_results, members)
            for key, members in self._METRIC_GROUPS.items()
        }
        true_status = group_results['definite']
        is_probable = group_results['probable'] == SiblingStatus.POSITIVE
        is_improbable = group_results['improbable'] == SiblingStatus.POSITIVE
        for group_key, result in group_results.items():
            self.metrics[group_key].add(result, true_status, is_probable, is_improbable)
        self.peer_stats.record(ip4, ip6, group_results)

    def _combine(self, evaluator_results: Dict[EvaluatorChoice, SiblingStatus], consider: Set[EvaluatorChoice]):
        return SiblingStatus.combine([
            status for evaluator, status in evaluator_results.items()
            if evaluator in consider
        ])


class Stats:
    def __init__(self, parent: Optional['Stats'] = None):
        self.provider_status_counts: Dict[EvaluatorChoice, Dict[SiblingStatus, int]] = \
            defaultdict(lambda: defaultdict(lambda: 0))
        self.overalls: Dict[SiblingStatus, int] = defaultdict(lambda: 0)
        self.seen_siblings: Set[str] = set()
        self.multi_siblings: Set[str] = set()
        self.sibling_pairs: List[Tuple[str, str]] = []
        self.starke_siblings: List[Tuple[str, str]] = []
        self.cross_stats: CrossStats = CrossStats()
        self.parent = parent

    def add_result(
            self,
            ip4: str, ip6: str,
            overall: SiblingStatus,
            evaluator_results: Dict[EvaluatorChoice, SiblingStatus]
    ):
        if self.parent:
            self.parent.add_result(ip4, ip6, overall, evaluator_results)
        for evaluator, status in evaluator_results.items():
            self.provider_status_counts[evaluator][status] += 1
        self.overalls[overall] += 1
        self.cross_stats.add(ip4, ip6, evaluator_results)
        if evaluator_results.get(EvaluatorChoice.ML_STARKE) == SiblingStatus.POSITIVE or \
                evaluator_results.get(EvaluatorChoice.TCPRAW_STARKE) == SiblingStatus.POSITIVE:
            self.starke_siblings.append((ip4, ip6))
        if overall == SiblingStatus.POSITIVE:
            self.sibling_pairs.append((ip4, ip6))
            if ip4 in self.seen_siblings:
                self.multi_siblings.add(ip4)
            else:
                self.seen_siblings.add(ip4)
            if ip6 in self.seen_siblings:
                self.multi_siblings.add(ip6)
            else:
                self.seen_siblings.add(ip6)
