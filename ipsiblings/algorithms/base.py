# algorithms.base.py
#
# (c) 2018 Marco Starke
#


import abc


class Algorithm(abc.ABC):
  
  @abc.abstractmethod
  def __init__(self, *args, **kwargs):
    pass
  
  @abc.abstractmethod
  def init(self, *args, **kwargs):
    """
    Additional initialization or reinitialization.
    """
    pass

  @abc.abstractmethod
  def run(self, *args, **kwargs):
    """
    Run the algorithm.
    """
    pass
