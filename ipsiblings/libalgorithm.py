# libalgorithm.py
#
# (c) 2018 Marco Starke
#


"""
Algorithm wrapper

Register new algorithms here.

"""


from algorithms.traceroute import TracerouteAlgorithm
from algorithms.mda import MdaAlgorithm
from algorithms.topdowntraceroute import TopDownTracerouteAlgorithm


ALGORITHMS = {
  'traceroute': TracerouteAlgorithm,
  'mda': MdaAlgorithm,
  'topdowntraceroute': TopDownTracerouteAlgorithm
}

def get_algorithm(algorithm, *args, **kwargs):

  if algorithm in ALGORITHMS:
    return ALGORITHMS[algorithm.lower()](*args, **kwargs)
  else:
    raise ValueError('No algorithm with name \'{0}\' found!'.format(algorithm))
