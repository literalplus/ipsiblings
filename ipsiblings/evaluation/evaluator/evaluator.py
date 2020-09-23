import abc

from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling


class SiblingEvaluator(metaclass=abc.ABCMeta):
    def __init__(self, key: str):
        self.key = key

    @abc.abstractmethod
    def evaluate(self, evaluated_sibling: EvaluatedSibling):
        raise NotImplementedError
