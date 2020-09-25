import abc
from typing import List

from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling


class SiblingEvaluator(metaclass=abc.ABCMeta):
    def __init__(self, key: str):
        self.key = key

    @abc.abstractmethod
    def evaluate(self, evaluated_sibling: EvaluatedSibling):
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], conf: AppConfig):
        raise NotImplementedError
