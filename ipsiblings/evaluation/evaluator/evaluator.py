import abc
import pathlib
from typing import List

from ipsiblings.config import AppConfig
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.model import const


class SiblingEvaluator(metaclass=abc.ABCMeta):
    """
    Abstract base class for sibling evaluators.
    """

    def __init__(self, key: const.EvaluatorChoice):
        self.key = key

    @abc.abstractmethod
    def evaluate(self, evaluated_sibling: EvaluatedSibling):
        raise NotImplementedError

    @classmethod
    @abc.abstractmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig):
        raise NotImplementedError
