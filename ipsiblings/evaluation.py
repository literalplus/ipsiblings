#!/usr/bin/env python3
#
# evaluation.py
#
# (c) 2019 Marco Starke
#

import gc
import os
import sys
import math
import pickle
import random
import pathlib
import datetime
import ipaddress
import traceback

import sklearn.feature_selection as fs
import sklearn.impute as imp
import sklearn.feature_extraction as fe
import sklearn.model_selection as ms
import sklearn.tree as tree # CART
import sklearn.neighbors as neighbors # KNN
import sklearn.metrics as metrics # matthews_corrcoef(y_true, y_pred, sample_weight = None)

import xgboost as xgb

import matplotlib.backends.backend_pdf

import numpy as np
import pandas as pd

import matplotlib.pyplot as plt

from ipsiblings.libts.serialization import load_candidate_pairs
from . import keyscan
from . import libts
from . import libgeo
from . import libtools
from . import libtrace
from . import libsiblings
from . import libconstants as const
from . import liblog
log = liblog.get_root_logger()
log.setLevel(liblog.CRITICAL) # set to critical to silence output except print()


class ProposedModel(object):

  def __init__(self, randomized_model, raw_ts_threshold = 0.305211037, raw_ts_thresh_column = 'raw_timestamp_diff'):
    if type(randomized_model) is str:
      with open(randomized_model, mode = 'rb') as infile:
        self.model = pickle.load(infile)
    else:
      self.model = randomized_model

    self.rawtsthresh = raw_ts_threshold
    self.rawtsthreshcolumn = raw_ts_thresh_column

  def fit(self, X, y, *args, **kwargs):
    x = X.drop(columns = [self.rawtsthreshcolumn]) # we train without the raw ts diff value
    self.model.fit(x, y, *args, **kwargs)

  def predict(self, pdframe, *args, **kwargs):
    if libtools.is_iterable(pdframe):
      out = []
      for i in range(len(pdframe)):
        row = pdframe.iloc[i] # gives Series
        if row[self.rawtsthreshcolumn] < self.rawtsthresh:
          out.append(True)
        else:
          row = row.drop(labels = [self.rawtsthreshcolumn])
          out.append(bool(self.model.predict(pd.DataFrame([row], columns = row.index), *args, **kwargs)[0]))
      return out
    else:
      if pdframe[0, self.rawtsthreshcolumn] < self.rawtsthresh:
        return True
      else:
        return bool(self.model.predict(pdframe)[0])

  def score(self, X, y):
    return NotImplemented


def now():
  return str(datetime.datetime.now())

def now_file():
  return str(datetime.datetime.now()).replace(':', '.').replace(' ', '_')


# def plot_append(siblings, pdfpages):
#   def pfunc(fig, pdf = None):
#     if pdf:
#       pdf.savefig(fig)
#
#   plotfunc = pfunc
#   args = { 'pdf': pdfpages }
#
#   counter = 0
#   for s in siblings:
#     if s.plot(func = plotfunc, funckwargs = args):
#       counter = counter + 1
#
#   return counter


def construct_evaluated_features_to_train(gt_dir, lrt = True, feature_keys = [ 'raw_timestamp_diff' ], split_nlnog_ripe = True, batch_size = 5000, timestamp_limit = None):
  print('{0} - Start loading true sibling data ...'.format(now()))

  valid_sibs = list(load_data(gt_dir, 'c', lrt = lrt, include_domain = True, limit_nr_timestamps = timestamp_limit).values())

  print('{0} - Finished loading true sibling data ... Started [ splitting and ] constructing false siblings ...'.format(now()))

  if split_nlnog_ripe:
    nlnog, ripe, unknown = split_nlnog_ripe_siblings(valid_sibs)
    void_sibs = []
    void_sibs.extend(construct_void_siblings_from_list(nlnog, lrt))
    void_sibs.extend(construct_void_siblings_from_list(ripe, lrt))
    if unknown:
      void_sibs.extend(construct_void_siblings_from_list(unknown, lrt))
  else:
    void_sibs = construct_void_siblings_from_list(valid_sibs, lrt)

  print('{0} - Finished constructing void siblings ... Started constructing true sibling features ...'.format(now()))
  # construct features for the true siblings
  X = construct_features(valid_sibs, keys = feature_keys)
  y = [ 1 for _ in range(len(valid_sibs)) ]
  valid_sibs.clear()
  gc.collect()
  print('{0} - Finished constructing true sibling features ... Started preparation of batches for void sibling feature construction ...'.format(now()))

  # now split the huge false siblings data set for feature construction
  X_void = []

  void_split = list(libtools.split_list(void_sibs, batch_size))
  void_sibs.clear()
  gc.collect()
  for vlist in void_split:
    X_void.extend(construct_features(vlist, keys = feature_keys))
    vlist.clear()
    gc.collect()

  print('{0} - Finished X and y construciton ...'.format(now()))

  X.extend(X_void)
  y.extend([ 0 for _ in range(len(X_void)) ])

  return (X, y)


def construct_model(gt_siblings, model_class, *args, lrt = True, feature_keys = [ 'raw_timestamp_diff' ], missing_values_handler = None, split_nlnog_ripe = True, batch_size = 5000, model_file_name = None, model_fimportance_fname = None, **kwargs):
  """
  gt_siblings             directory of training data or list of siblings already evaluated
  model_class             model class which should be instantiated
  *args                   any positional arguments which should be given to model_class
  feature_keys            keys to be used for calculations and model training
  missing_values_handler  None or callable which takes two arguments X and y and returns X and y processed
  split_nlnog_ripe        split the nlnog and ripe siblings to form corresponding void siblings [only if no sibling objects provided]
  batch_size              handle feature construction in size of batch_size batches [only if no sibling objects provided]
  model_file_name         None/False or file to which the model should be pickled
  model_fimportance_fname file name for feature importance chart to plot [None]
  **kwargs                any keyword arguments which should be given to model_class
  """
  if isinstance(gt_siblings, str) or isinstance(gt_siblings, pathlib.PurePath):

    X, y = construct_evaluated_features_to_train(gt_siblings, lrt = lrt, feature_keys = feature_keys, split_nlnog_ripe = split_nlnog_ripe, batch_size = batch_size)

    X = pd.DataFrame(X, columns = feature_keys)

  elif isinstance(gt_siblings, tuple):
    X, y = gt_siblings

    X = pd.DataFrame(X, columns = feature_keys)

  else:
    print('Invalid sibling source provided!')
    return None

  # if mcc_weights:
  #   weights = get_weights_X_y(X, pd.DataFrame(y, columns = ['y_train']), 'y_train')
  # else:
  #   weights = None

  if missing_values_handler:
    X, y = missing_values_handler(X, y)

  model = model_class(*args, **kwargs)
  model.fit(X, y)

  print('{0} - Finished model training ...'.format(now()))

  if model_file_name:
    print('{0} - Now pickling model to file [{1}] ...'.format(now(), model_file_name))
    with open(model_file_name, mode = 'wb') as outfile:
      pickle.dump(model, outfile)

    if model_fimportance_fname:
      print('{0} - Now printing feature importance to file [{1}] ...'.format(now(), model_fimportance_fname))

      pdf_features = matplotlib.backends.backend_pdf.PdfPages(model_fimportance_fname)

      plt.rcParams['figure.figsize'] = [15, 10]
      fig = plt.figure(dpi = 256)
      axes = plt.subplot(111)
      xgb.plot_importance(model, ax = axes, height = 0.5, color = 'lightgreen',  edgecolor = 'black', title = 'Feature Importance', xlabel = 'F-score', ylabel = 'Features', importance_type = 'weight', grid = False, show_values = True)
      pdf_features.savefig(fig)
      plt.close(fig)
      pdf_features.close()

  return model


def evaluate_router_traces(base_dir, model, lrt, feature_keys):
  base_path = pathlib.Path(base_dir)
  dirs = [ x for x in base_path.iterdir() if x.is_dir() ]

  edge_routers = 0
  intermediate_routers = 0
  edge_siblings = 0
  intermediate_siblings = 0

  for dir in dirs:
    print('{0} - Now processing: {1}'.format(now(), dir))
    nr_edge_routers, nr_intermediate_routers, nr_siblings_edge_routers, nr_siblings_intermediate_routers = evaluate_routers(dir, model, lrt = lrt, feature_keys = feature_keys)
    edge_routers = edge_routers + nr_edge_routers
    intermediate_routers = intermediate_routers + nr_intermediate_routers
    edge_siblings = edge_siblings + nr_siblings_edge_routers
    intermediate_siblings = intermediate_siblings + nr_siblings_intermediate_routers

  print('{0} - Finished'.format(now()))

  print('                      Edge routers: {0}'.format(edge_routers))
  print('        Edge siblings/non-siblings: {0} / {1}'.format(edge_siblings, edge_routers - edge_siblings))
  print('              Intermediate routers: {0}'.format(intermediate_routers))
  print('Intermediate siblings/non-siblings: {0} / {1}'.format(intermediate_siblings, intermediate_routers - intermediate_siblings))

# IPv4 https://www.ripe.net/publications/docs/ripe-708 -> /22
# IPv6 minimum allocation: https://www.ripe.net/publications/docs/ripe-707 -> /32
def evaluate_routers(directory, model, lrt = False, feature_keys = [ 'raw_timestamp_diff' ], return_objects = False, edge_prefix_v4 = '/22', edge_prefix_v6 = '/32'):
  """
  Evaluate all nodes within given trace set directory.

  if return_objects == True:
    return (nr_edge_routers, nr_intermediate_routers, nr_siblings_edge_routers, nr_siblings_intermediate_routers, siblings_edge, non_siblings_edge, siblings_intermediate, non_siblings_intermediate)
  else:
    return (nr_edge_routers, nr_intermediate_routers, nr_siblings_edge_routers, nr_siblings_intermediate_routers)
  """

  tracesets = libtrace.load_trace_sets(directory)
  candidates = list(libsiblings.construct_trace_candidates(tracesets, all_ports_timestamps = False, low_runtime = lrt, add_traces = True).values())
  del tracesets
  gc.collect()

  nr_edge_routers = 0
  nr_intermediate_routers = 0
  nr_siblings_edge_routers = 0
  nr_siblings_intermediate_routers = 0

  siblings_edge, non_siblings_edge = [], []
  siblings_intermediate, non_siblings_intermediate = [], []

  edge_nets4 = set()
  edge_nets6 = set()

  for c in candidates: # prepare for prediction
    c.evaluate()
    traces, _ = c.trace_data
    for trace in traces: # multiple traces per sibcandidate of which each consists of (v4trace, v6trace)
      # take last hop of each trace, build network and add this network to the set
      try:
        net4 = ipaddress.ip_network('{0}{1}'.format(trace[0][-1], edge_prefix_v4), strict = False)
        edge_nets4.add(net4)
      except ValueError as e:
        print('IPv4 network construction ValueError: {0}'.format(e))
      try:
        net6 = ipaddress.ip_network('{0}{1}'.format(trace[1][-1], edge_prefix_v6), strict = False)
        edge_nets6.add(net6)
      except ValueError as e:
        print('IPv6 network construction ValueError: {0}'.format(e))

  try:
    while True:
      sibcand = candidates.pop()
      ip4, ip6 = ipaddress.ip_address(sibcand.ip4), ipaddress.ip_address(sibcand.ip6)
      is_edge4 = False
      is_edge6 = False
      for net in edge_nets4:
        if ip4 in net:
          is_edge4 = True
          break
      for net in edge_nets6:
        if ip6 in net:
          is_edge6 = True
          break

      # employ proposed prediction model
      if sibcand.is_sibling == True: # is set in evaluate() which was called previously -> check raw_timestamp_diff < 0.305211037
        # verifying metric -> if < raw_ts_diff_threshold (0.3052) -> IP Sibling with constant timestamp offset
        is_sibling = True
      else:
        is_sibling = model.predict(pd.DataFrame([sibcand.get_features(key_list = feature_keys, substitute_none = np.nan)], columns = feature_keys))[0] # should only have 1 result

      if is_edge4 and is_edge6:
        nr_edge_routers = nr_edge_routers + 1
        if is_sibling:
          nr_siblings_edge_routers = nr_siblings_edge_routers + 1
          if return_objects:
            siblings_edge.append(sibcand)
        else:
          if return_objects:
            non_siblings_edge.append(sibcand)
      else:
        nr_intermediate_routers = nr_intermediate_routers + 1
        if is_sibling:
          nr_siblings_intermediate_routers = nr_siblings_intermediate_routers + 1
          if return_objects:
            siblings_intermediate.append(sibcand)
        else:
          if return_objects:
            non_siblings_intermediate.append(sibcand)

  except IndexError: # all elements have been popped
    pass

  if return_objects:
    return (nr_edge_routers, nr_intermediate_routers, nr_siblings_edge_routers, nr_siblings_intermediate_routers, siblings_edge, non_siblings_edge, siblings_intermediate, non_siblings_intermediate)
  else:
    return (nr_edge_routers, nr_intermediate_routers, nr_siblings_edge_routers, nr_siblings_intermediate_routers)


def load_data(basedir, type, lrt = True, include_domain = True, limit_nr_timestamps = None):
  """
  Combine all batches into one dictionary.
  Construct SiblingCandidate or LowRTSiblingCandidate objects and returns them.
  May be time consuming!

  type    'trace' or 'candidate' ('t' or 'c') for trace or candidate objects
  lrt     low runtime (LowRTSiblingCandidate instead of SiblingCandidate object) [True]
  include_domain    in the candidate pairs file the domain is available to be loaded [True]
  """
  base = pathlib.Path(basedir)
  sibcandidates = {}
  # construct sibling candidates for each directory to prevent overwriting (keys of the sibcandidates dict are 'ip4_port4_ip6_port6')
  if type.lower() in ('t', 'trace'):
    for dir in base.iterdir():
      if not dir.is_dir():
        continue
      tset = libtrace.load_trace_sets(dir)
      sibcands = libsiblings.construct_trace_candidates(tset, low_runtime = lrt)
      sibcandidates = { **sibcandidates, **sibcands }
      tset.clear()
      gc.collect()

    if not sibcandidates: # we do not have any batches just the current directory (e.g. ground truth data)
      tset = libtrace.load_trace_sets(base)
      sibcandidates = libsiblings.construct_trace_candidates(tset, low_runtime = lrt)
      tset.clear()
      gc.collect()

  elif type.lower() in ('c', 'candidate'):
    for dir in base.iterdir():
      if not dir.is_dir():
        continue
      candidate_file = dir / const.CANDIDATE_PAIRS_FILE_NAME
      _, _, _, cpairs = load_candidate_pairs(candidate_file, include_domain = include_domain)
      if limit_nr_timestamps:
        sibcands = libsiblings.construct_node_candidates(cpairs, low_runtime = True, nr_timestamps = limit_nr_timestamps)
      else:
        sibcands = libsiblings.construct_node_candidates(cpairs, low_runtime = lrt)

      sibcandidates = { **sibcandidates, **sibcands }
      cpairs.clear()
      gc.collect()

    if not sibcandidates: # we do not have any batches just the current directory (e.g. ground truth data)
      candidate_file = base / const.CANDIDATE_PAIRS_FILE_NAME
      _, _, _, cpairs = load_candidate_pairs(candidate_file, include_domain = include_domain)
      if limit_nr_timestamps:
        sibcandidates = libsiblings.construct_node_candidates(cpairs, low_runtime = True, nr_timestamps = limit_nr_timestamps)
      else:
        sibcandidates = libsiblings.construct_node_candidates(cpairs, low_runtime = lrt)
      cpairs.clear()
      gc.collect()

  else:
    log.error('Unknown type provided, use "trace" ("t") or "candidate" ("c") to select type of data to be loaded!')
    return None

  return sibcandidates

# constructors
# SiblingCandidate(ip4, ip6, port4, port6, ip4_ts, ip6_ts, ip4_tcpopts, ip6_tcpopts, domains = None, ssh_available = False, ssh_keys = None, trace_set_id = None)
# LowRTSiblingCandidate(ip4, ip6, port4, port6, ip4_ts, ip6_ts, ip4_tcpopts, ip6_tcpopts, nr_timestamps = None, domains = None, ssh_available = False, ssh_keys = None, trace_set_id = None)
def construct_void_siblings(siblings, lrt):
  keys = list(siblings.keys())
  void_siblings = []

  for sibkey, validsib in siblings.items():
    for k in keys:
      if k == sibkey: # skip current sibling candidate
        continue
      # construct new non-matching sibling candidates
      currentsib = siblings[k]
      if validsib.ssh4 and currentsib.ssh6:
        ssh_available = True
      else:
        ssh_available = False
      ssh_keys = { 4: validsib.ssh4, 6: currentsib.ssh6 }
      if lrt:
        s = libsiblings.LowRTSiblingCandidate(validsib.ip4, currentsib.ip6, validsib.port4, currentsib.port6, validsib.ip4_ts, currentsib.ip6_ts, validsib.ip4_tcpopts, currentsib.ip6_tcpopts, ssh_available = ssh_available, ssh_keys = ssh_keys)
      else:
        s = libsiblings.SiblingCandidate(validsib.ip4, currentsib.ip6, validsib.port4, currentsib.port6, validsib.ip4_ts, currentsib.ip6_ts, validsib.ip4_tcpopts, currentsib.ip6_tcpopts, ssh_available = ssh_available, ssh_keys = ssh_keys)
      s.addsshagent(validsib.agent4, const.IP4)
      s.addsshagent(currentsib.agent6, const.IP6)
      void_siblings.append(s)

  return void_siblings


def construct_void_siblings_from_list(siblings, lrt):
  void_siblings = []
  for validsib in siblings:
    for currentsib in siblings:
      if validsib == currentsib:
        continue

      if validsib.ssh4 and currentsib.ssh6:
        ssh_available = True
      else:
        ssh_available = False
      ssh_keys = { 4: validsib.ssh4, 6: currentsib.ssh6 }
      if lrt:
        s = libsiblings.LowRTSiblingCandidate(validsib.ip4, currentsib.ip6, validsib.port4, currentsib.port6, validsib.ip4_ts, currentsib.ip6_ts, validsib.ip4_tcpopts, currentsib.ip6_tcpopts, ssh_available = ssh_available, ssh_keys = ssh_keys)
      else:
        s = libsiblings.SiblingCandidate(validsib.ip4, currentsib.ip6, validsib.port4, currentsib.port6, validsib.ip4_ts, currentsib.ip6_ts, validsib.ip4_tcpopts, currentsib.ip6_tcpopts, ssh_available = ssh_available, ssh_keys = ssh_keys)
      s.addsshagent(validsib.agent4, const.IP4)
      s.addsshagent(currentsib.agent6, const.IP6)
      void_siblings.append(s)

  return void_siblings


def construct_test_data(basedir, lrt = True):
  """
  Returns (valid_sibs, void_sibs, len(void_sibs), len(nlnog_void_sibs), len(ripe_void_sibs), len(unknown_void_sibs))
  """
  valid_sibs = load_data(basedir, 'c', lrt = lrt, include_domain = True)

  keyfile = pathlib.Path(basedir, const.SSH_KEYS_FILENAME)
  agentfile = pathlib.Path(basedir, const.SSH_AGENTS_FILENAME)
  keyscan.assign_key_data(valid_sibs, keyfile, agentfile)

  nlnog_sibs = {}
  ripe_sibs = {}
  unknown = {}

  for key, sib in valid_sibs.items():
    if not sib.domains:
      log.debug('SiblingCandidate has no domain: {0}'.format(str(sib)))
      continue
    if 'nlnog' in ','.join(sib.domains).lower():
      nlnog_sibs[key] = sib
    elif 'ripe' in ','.join(sib.domains).lower():
      ripe_sibs[key] = sib
    else:
      unknown[key] = sib

  if unknown:
    unknown_void = construct_void_siblings(unknown, lrt)
  else:
    unknown_void = []

  nlnog_void = construct_void_siblings(nlnog_sibs, lrt) # ssh enabled
  ripe_void = construct_void_siblings(ripe_sibs, lrt) # ssh disabled
  void_sibs = [ *nlnog_void, *ripe_void, *unknown_void ]

  return (list(valid_sibs.values()), void_sibs, len(void_sibs), len(nlnog_void), len(ripe_void), len(unknown_void))

def split_nlnog_ripe_siblings(siblings):
  nlnog_sibs = []
  ripe_sibs = []
  unknown = []

  for sib in siblings:
    if not sib.domains:
      unknown.append(sib)
      continue
    if 'nlnog' in ','.join(sib.domains).lower():
      nlnog_sibs.append(sib)
    elif 'ripe' in ','.join(sib.domains).lower():
      ripe_sibs.append(sib)
    else:
      unknown.append(sib)

  return (nlnog_sibs, ripe_sibs, unknown)


# SiblingCandidate.get_features()
#   => keys = [ 'hz4', 'hz6', 'hz_diff', 'hz4_R2', 'hz6_R2', 'raw_timestamp_diff', 'alpha4', 'alpha6', 'alphadiff', 'rsqr4', 'rsqr6', 'rsqrdiff', 'dynrange4', 'dynrange6', 'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel', 'spl_diff', 'spl_diff_scaled', 'ssh_keys_match', 'ssh_agents_match', geo4, geo6 ]
def construct_features(siblings, keys = None, ignore_invalid = False, return_invalid = False):
  features = []
  invalid = []
  for s in siblings:
    try:
      s.evaluate()
      if ignore_invalid:
        sibfeatures = s.get_features(key_list = keys)
        if not all(sibfeatures.values()):
          invalid.append(s)
          continue
        else:
          features.append(sibfeatures)
      else:
        features.append(s.get_features(key_list = keys))
    except Exception as e:
      exc_type, exc_object, exc_traceback = sys.exc_info()
      ef = traceback.extract_tb(exc_traceback)[-1] # get the inner most error frame
      string = '{0} in {1} (function: \'{2}\') at line {3}: "{4}" <{5}>'.format(exc_type.__name__, os.path.basename(ef.filename), ef.name, ef.lineno, str(e), ef.line)
      log.error(string)
      print(string)

  if return_invalid:
    return (features, invalid)
  else:
    return features


def select_features(X, y, selector = fs.SelectKBest, score_func = fs.mutual_info_classif, transform = True, **kwargs):
  if transform:
    return selector(score_func, **kwargs).fit_transform(X, y)
  else:
    return selector(score_func, **kwargs).fit(X, y)


def stats(y_true, y_pred, raw = False):
  """
  Expects pandas.DataFrame or to pandas.DataFrame convertible.
  """
  # https://github.com/tumi8/siblings/blob/master/src/eval/siblings_ml.ipynb
  if type(y_true) != pd.DataFrame:
    try:
      y_true = pd.DataFrame(y_true, columns = ['y_true'])['y_true']
    except:
      return [ None for _ in range(12) ]
  if type(y_pred) != pd.DataFrame:
    try:
      y_pred = pd.DataFrame(y_pred, columns = ['y_pred'])['y_pred']
    except:
      return [ None for _ in range(12) ]

  tp = np.sum((y_true == 1) & (y_pred == 1))
  fp = np.sum(y_true < y_pred)
  tn = np.sum((y_true == 0) & (y_pred == 0))
  fn = np.sum(y_true > y_pred)

  rates = (tp, fp, tn, fn)

  if raw:
    factor = 1
  else:
    factor = 100

  try:
    P = (tp + fn)
    N = (fp + tn)
    Pp = (tp + fp)
    Nn = (fn + tn)

    sensitivity = factor * tp / P # Recall
    specificity = factor * tn / N # True Negative Rate (TNR)
    precision = factor * tp / Pp # Positive Predictive Value (PPV)
    negative_predictive_value = factor * tn / Nn # NPV
    false_negative_rate = factor * fn / P # FNR, miss rate
    false_positive_rate = factor * fp / N # FPR, fall-out
    false_discovery_rate = factor * fp / Pp # FDR
    false_omission_rate = factor * fn / Nn # FOR

    accuracy = factor * (tp + tn) / (P + N) # ACC
    f1_score = 2 * ((precision * sensitivity) / (precision + sensitivity))
    mcc = (tp * tn - fp * fn) / math.sqrt(Pp * P * N * Nn) # Matthews Correlation Coefficient
  except:
    return [ None for _ in range(12) ]

  return (sensitivity, specificity, precision, negative_predictive_value, false_negative_rate, false_positive_rate, false_discovery_rate, false_omission_rate, accuracy, f1_score, mcc, rates)

def get_weights_split(len_sib, len_nonsib, y_true):
  len_total = len_sib + len_nonsib
  sib_weight = len_sib / float(len_total)
  nonsib_weight = len_nonsib / float(len_total)
  if len_total != len(y_true):
    return None
  weights = np.array(y_true, dtype = np.float32)
  weights[weights == 1] = sib_weight
  weights[weights == 0] = nonsib_weight
  return weights

def get_weights(X_df, y_colname):
  len_sib = len(X_df[X_df[y_colname] == 1])
  len_nonsib = len(X_df[X_df[y_colname] == 0])
  len_total = len_sib + len_nonsib
  sib_weight = len_sib / float(len_total)
  nonsib_weight = len_nonsib / float(len_total)
  weights = np.float32(X_df[y_colname].to_numpy())
  weights[weights == 1] = sib_weight
  weights[weights == 0] = nonsib_weight
  return weights

def get_weights_X_y(X_df, y_df, y_colname):
  len_sib = len(X_df[y_df[y_colname] == 1])
  len_nonsib = len(X_df[y_df[y_colname] == 0])
  len_total = len_sib + len_nonsib
  sib_weight = len_sib / float(len_total)
  nonsib_weight = len_nonsib / float(len_total)
  weights = np.float32(y_df[y_colname].to_numpy())
  weights[weights == 1] = sib_weight
  weights[weights == 0] = nonsib_weight
  return weights

def scheitle_evaluation(data_directory, lrt = True, test_size = 0.33, feature_keys = None, mcc_weights = False, batch_size = 5000, split_nlnog_ripe = False, print_tree = True):
  if not feature_keys:
    feature_keys = [ 'raw_timestamp_diff' ]

  valid_sibs = load_data(data_directory, 'c', lrt = lrt, include_domain = True)
  # keyfile = pathlib.Path(data_directory, const.SSH_KEYS_FILENAME)
  # agentfile = pathlib.Path(data_directory, const.SSH_AGENTS_FILENAME)
  # keyscan.assign_key_data(valid_sibs, keyfile, agentfile)

  # before building non-sibling pairs, Scheitle et al. split the siblings and produced non-siblings from the respective candidate set
  S_train, S_test, y_train, y_test = ms.train_test_split(list(valid_sibs.values()), [ 1 for _ in range(len(valid_sibs)) ], test_size = test_size, random_state = 42)

  print('{0} - Loaded and split true sibling data ... Now constructing false siblings ...'.format(now()))

  if split_nlnog_ripe:
    nlnog_train, ripe_train, unknown_train = split_nlnog_ripe_siblings(S_train)
    nlnog_test, ripe_test, unknown_test = split_nlnog_ripe_siblings(S_test)

    void_train = []
    void_test = []

    void_train.extend(construct_void_siblings_from_list(nlnog_train, lrt))
    void_train.extend(construct_void_siblings_from_list(ripe_train, lrt))
    if unknown_train:
      void_train.extend(construct_void_siblings_from_list(unknown_train, lrt))

    void_test.extend(construct_void_siblings_from_list(nlnog_test, lrt))
    void_test.extend(construct_void_siblings_from_list(ripe_test, lrt))
    if unknown_test:
      void_test.extend(construct_void_siblings_from_list(unknown_test, lrt))

  else:
    void_train = construct_void_siblings_from_list(S_train, lrt)
    void_test = construct_void_siblings_from_list(S_test, lrt)

  print('{0} - Constructed void data ... Now constructing true sibling features ...'.format(now()))

  # construct features for the true siblings
  X_train = construct_features(S_train, keys = feature_keys)
  X_test = construct_features(S_test, keys = feature_keys)
  S_train.clear()
  S_test.clear()
  gc.collect()

  print('{0} - Constructed features of true siblings ... Now constructing false sibling features for training ...'.format(now()))

  # now split the huge false siblings data set for feature construction
  X_train_void = []
  X_test_void = []

  void_train_split = list(libtools.split_list(void_train, batch_size))
  void_train.clear()
  gc.collect()
  for vlist in void_train_split:
    X_train_void.extend(construct_features(vlist, keys = feature_keys))
    vlist.clear()
    gc.collect()

  print('{0} - Constructed features of false siblings for training ... Now constructing false sibling features for testing ...'.format(now()))

  void_test_split = list(libtools.split_list(void_test, batch_size))
  void_test.clear()
  gc.collect()
  for vlist in void_test_split:
    X_test_void.extend(construct_features(vlist, keys = feature_keys))
    vlist.clear()
    gc.collect()

  print('{0} - Constructed features of false siblings for testing ... Now preparing data and weights and performing training ...'.format(now()))

  X_train.extend(X_train_void)
  y_train.extend([0 for _ in range(len(X_train_void))])
  X_test.extend(X_test_void)
  y_test.extend([0 for _ in range(len(X_test_void))])

  # this is useless since it does not work with NaN entries => impute values or remove rows
  # if not low_runtime: # do feature selection for full runtime -> dropna() resulted in 0 rows with all features ...
  #   print('{0} - Performing feature selection ...'.format(now()))
  #   v_train = fe.DictVectorizer()
  #   v_test = fe.DictVectorizer()
  #   X_train = v_train.fit_transform(X_train)
  #   X_test = v_test.fit_transform(X_test)
  #
  #   X_train = imp.SimpleImputer(missing_values = np.nan, strategy = 'mean').fit_transform(X_train, y_train)
  #
  #   # feature selection # https://scikit-learn.org/stable/modules/feature_selection.html#tree-based-feature-selection
  #   fselector = select_features(X_train, y_train, selector = fs.SelectKBest, score_func = fs.mutual_info_classif, transform = False, k = 8)
  #   # update feature_keys
  #   feature_keys = v_train.restrict(fselector.get_support()).get_feature_names()
  #   # reduce vectorized features to selected ones
  #   X_train = fselector.transform(X_train)
  #   X_test = fselector.transform(X_test)
  #   v_train = None
  #   v_test = None
  #   gc.collect()
  #   print('{0} - Selected features:'.format(now()))
  #   print('{0} - {1}'.format(now(), feature_keys))
  #   print('{0} - Finished feature selection ... Continuing with data preparation ...'.format(now()))


  X_train = pd.DataFrame(X_train).join(pd.DataFrame(y_train, columns = ['y_train']))
  X_test = pd.DataFrame(X_test).join(pd.DataFrame(y_test, columns = ['y_test']))

  xtrain_before = len(X_train)
  xtest_before = len(X_test)
  print('{0} - Before dropna() - training samples: {1:6} - test samples: {2:6}'.format(now(), xtrain_before, xtest_before))
  X_train = X_train.dropna() # e.g. subset = ['raw_ts_diff']
  X_test = X_test.dropna()
  xtrain_after = len(X_train)
  xtest_after = len(X_test)
  print('{0} -  After dropna() - training samples: {1:6} - test samples: {2:6} - train difference: {3:6} - test difference: {4:6}'.format(now(), xtrain_after, xtest_after, xtrain_before - xtrain_after, xtest_before - xtest_after))

  if mcc_weights:
    train_weights = get_weights(X_train, 'y_train')
    test_weights = get_weights(X_test, 'y_test')
  else:
    train_weights = None
    test_weights = None

  y_train = X_train['y_train'].to_frame()
  X_train = X_train.drop(['y_train'], axis = 1) # 1 -> column
  y_test = X_test['y_test'].to_frame()
  X_test = X_test.drop(['y_test'], axis = 1)

  # clf = neighbors.KNeighborsClassifier(n_neighbors = 7, weights = 'distance', p = 2, n_jobs = 4) # p = 2 => use euclidian distance for weights
  if low_runtime:
    clf = tree.DecisionTreeClassifier(max_depth = 10) # low runtime
  else:
    clf = tree.DecisionTreeClassifier(max_depth = 30, min_samples_leaf = 5, random_state = 42) # full runtime (scheitle)
  clf.fit(X_train, y_train)

  if print_tree and type(clf) == tree.DecisionTreeClassifier:
    cur_time = now_file()
    if lrt:
      tree.export_graphviz(clf, out_file = '/root/thesis/data/_DATA/eval/lrt_cmp_scheitle_CART_{0}.dot'.format(cur_time), feature_names = feature_keys, filled = True, rounded = True)
      with open('/root/thesis/data/_DATA/xgb_eval/lrt_cmp_scheitle_CART_{0}.pickle'.format(cur_time), mode = 'wb') as outfile:
        pickle.dump(clf, outfile)
    else:
      tree.export_graphviz(clf, out_file = '/root/thesis/data/_DATA/eval/frt_cmp_scheitle_CART_{0}.dot'.format(cur_time), feature_names = feature_keys, filled = True, rounded = True)
      with open('/root/thesis/data/_DATA/xgb_eval/frt_cmp_scheitle_CART_{0}.pickle'.format(cur_time), mode = 'wb') as outfile:
        pickle.dump(clf, outfile)

  print('{0} - Training complete, starting predictions and calculations ...'.format(now()))

  y_pred_train = clf.predict(X_train)
  y_pred_test = clf.predict(X_test)

  cv_results = ms.cross_val_score(clf, X_test, y_test, cv = 10)

  (sensitivity_train, specificity_train, precision_train, negative_predictive_value_train, false_negative_rate_train, false_positive_rate_train, false_discovery_rate_train, false_omission_rate_train, accuracy_train, f1_score_train, mcc_train, rates_train) = stats(y_train['y_train'], y_pred_train, raw = True)
  (sensitivity_test, specificity_test, precision_test, negative_predictive_value_test, false_negative_rate_test, false_positive_rate_test, false_discovery_rate_test, false_omission_rate_test, accuracy_test, f1_score_test, mcc_test, rates_test) = stats(y_test['y_test'], y_pred_test, raw = True)

  print('test             10-fold cv: {0}'.format(', '.join([str(val) for val in cv_results])))
  print('test         10-fold cv avg: {0}'.format(np.mean(cv_results, dtype = np.float64)))
  print('train                 rates: {0} TP, {1} FP, {2} TN, {3} FN'.format(*rates_train))
  print('test                  rates: {0} TP, {1} FP, {2} TN, {3} FN'.format(*rates_test))
  print('test precision (clf, stats): {0}, {1}'.format(clf.score(X_test, y_test), precision_test))
  print('test   sens, spec, npv, fnr: {0}, {1}, {2}, {3}'.format(sensitivity_test, specificity_test, negative_predictive_value_test, false_negative_rate_test))
  print('test fpr, fdr, for, acc, f1: {0}, {1}, {2}, {3}, {4}'.format(false_positive_rate_test, false_discovery_rate_test, false_omission_rate_test, accuracy_test, f1_score_test))
  print('train  mcc (sklearn, stats): {0}, {1}'.format(metrics.matthews_corrcoef(y_train, y_pred_train, sample_weight = train_weights), mcc_train))
  print('test   mcc (sklearn, stats): {0}, {1}'.format(metrics.matthews_corrcoef(y_test, y_pred_test, sample_weight = test_weights), mcc_test))


################################################################################
################################################################################
################################################################################
################################################################################
################################################################################
################################################################################

def xgb_evaluation(data_directory, output_directory = None, own_model = False, lrt = True, test_size = 0.33, feature_keys = None, mcc_weights = False, batch_size = 5000, split_nlnog_ripe = False, print_tree = True, limit_nr_timestamps = None):
  if not feature_keys:
    feature_keys = [ 'raw_timestamp_diff' ]

  if output_directory is not None:
    output_directory = pathlib.Path(output_directory)
  else:
    if print_tree:
      print('{0} - No output directory given -> no trees and features will be printed ...'.format(now()))
      print_tree = False

  valid_sibs = load_data(data_directory, 'c', lrt = lrt, include_domain = True, limit_nr_timestamps = limit_nr_timestamps)
  # keyfile = pathlib.Path(data_directory, const.SSH_KEYS_FILENAME)
  # agentfile = pathlib.Path(data_directory, const.SSH_AGENTS_FILENAME)
  # keyscan.assign_key_data(valid_sibs, keyfile, agentfile)

  # before building non-sibling pairs, Scheitle et al. split the siblings and produced non-siblings from the respective candidate set
  S_train, S_test, y_train, y_test = ms.train_test_split(list(valid_sibs.values()), [ 1 for _ in range(len(valid_sibs)) ], test_size = test_size, random_state = 42)

  print('{0} - Loaded and split true sibling data ... Now constructing false siblings ...'.format(now()))

  if split_nlnog_ripe:
    nlnog_train, ripe_train, unknown_train = split_nlnog_ripe_siblings(S_train)
    nlnog_test, ripe_test, unknown_test = split_nlnog_ripe_siblings(S_test)

    void_train = []
    void_test = []

    void_train.extend(construct_void_siblings_from_list(nlnog_train, lrt))
    void_train.extend(construct_void_siblings_from_list(ripe_train, lrt))
    if unknown_train:
      void_train.extend(construct_void_siblings_from_list(unknown_train, lrt))

    void_test.extend(construct_void_siblings_from_list(nlnog_test, lrt))
    void_test.extend(construct_void_siblings_from_list(ripe_test, lrt))
    if unknown_test:
      void_test.extend(construct_void_siblings_from_list(unknown_test, lrt))

  else:
    void_train = construct_void_siblings_from_list(S_train, lrt)
    void_test = construct_void_siblings_from_list(S_test, lrt)

  print('{0} - Constructed void data ... Now constructing true sibling features ...'.format(now()))

  # construct features for the true siblings
  X_train = construct_features(S_train, keys = feature_keys)
  X_test = construct_features(S_test, keys = feature_keys)
  S_train.clear()
  S_test.clear()
  gc.collect()

  print('{0} - Constructed features of true siblings ... Now constructing false sibling features for training ...'.format(now()))

  # now split the huge false siblings data set for feature construction
  X_train_void = []
  X_test_void = []

  void_train_split = list(libtools.split_list(void_train, batch_size))
  void_train.clear()
  gc.collect()
  for vlist in void_train_split:
    X_train_void.extend(construct_features(vlist, keys = feature_keys))
    vlist.clear()
    gc.collect()

  print('{0} - Constructed features of false siblings for training ... Now constructing false sibling features for testing ...'.format(now()))

  void_test_split = list(libtools.split_list(void_test, batch_size))
  void_test.clear()
  gc.collect()
  for vlist in void_test_split:
    X_test_void.extend(construct_features(vlist, keys = feature_keys))
    vlist.clear()
    gc.collect()

  print('{0} - Constructed features of false siblings for testing ... Now preparing data and weights and performing training ...'.format(now()))

  X_train.extend(X_train_void)
  y_train.extend([0 for _ in range(len(X_train_void))])
  X_test.extend(X_test_void)
  y_test.extend([0 for _ in range(len(X_test_void))])

  X_train = pd.DataFrame(X_train, columns = feature_keys)
  X_test = pd.DataFrame(X_test, columns = feature_keys)

  if mcc_weights:
    train_weights = get_weights_X_y(X_train, pd.DataFrame(y_train, columns = ['y_train']), 'y_train')
    test_weights = get_weights_X_y(X_test, pd.DataFrame(y_test, columns = ['y_test']), 'y_test')
  else:
    train_weights = None
    test_weights = None

  # # replace None object of ssh_* features with another value to introduce a third state
  # X_train['ssh_keys_match'].fillna(value = -1, inplace = True) # was 42
  # X_train['ssh_agents_match'].fillna(value = -1, inplace = True)
  # X_test['ssh_keys_match'].fillna(value = -1, inplace = True)
  # X_test['ssh_agents_match'].fillna(value = -1, inplace = True)
  # X_train['ssh_keys_match'] = X_train['ssh_keys_match'].astype(int)
  # X_train['ssh_agents_match'] = X_train['ssh_agents_match'].astype(int)
  # X_test['ssh_keys_match'] = X_test['ssh_keys_match'].astype(int)
  # X_test['ssh_agents_match'] = X_test['ssh_agents_match'].astype(int)


  if own_model:
    clf = ProposedModel(xgb.XGBClassifier())
  else:
    params = { 'eta': 0.1, 'n_estimators': 800, 'max_depth': 4, 'min_child_weight': 6, 'gamma': 0.05, 'subsample': 0.6, 'colsample_bytree': 0.6, 'nthread': 4 }

    if low_runtime: # tune parameters ?!
      clf = xgb.XGBClassifier(**params) # max_depth = 10, random_state = 42) # objective = 'binary:logistic', booster = 'gbtree', max_depth = 10, n_estimators = 64, learning_rate = 0.01, subsample = 0.5, random_state = 42, missing = np.nan)
    else:
      clf = xgb.XGBClassifier(**params) # max_depth = 10, random_state = 42) # objective = 'binary:logistic', booster = 'gbtree', max_depth = 10, n_estimators = 64, learning_rate = 0.01, subsample = 0.5, random_state = 42, missing = np.nan)

  clf.fit(X_train, y_train) # eval_set = [(X_test, y_test)], early_stopping_rounds = 16, verbose = False)

  # If early stopping occurs, the model will have three additional fields: bst.best_score, bst.best_iteration and bst.best_ntree_limit.
  # bst.best_ntree_limit is the ntree_limit parameter default value in predict method if not any other value is specified.
  # Use bst.best_ntree_limit to get the correct value if num_parallel_tree and/or num_class appears in the parameters.
  best_score = getattr(clf, 'best_score', None)
  best_iteration = getattr(clf, 'best_iteration', None)
  best_ntree_limit = getattr(clf, 'best_ntree_limit', None)

  if limit_nr_timestamps:
    add_ts_nr = '_{0}'.format(limit_nr_timestamps)
  else:
    add_ts_nr = ''

  if print_tree:
    if lrt:
      identifier = 'lrt'
    else:
      identifier = 'frt'

    cur_time = now_file()

    pdf_features = matplotlib.backends.backend_pdf.PdfPages(output_directory / 'xgb_{0}_{1}{2}.features.pdf'.format(identifier, cur_time, add_ts_nr))
    pdf_trees = matplotlib.backends.backend_pdf.PdfPages(output_directory / 'xgb_{0}_{1}{2}.trees.pdf'.format(identifier, cur_time, add_ts_nr))
    clf.save_model(str(output_directory / 'xgb_{0}_{1}{2}.model'.format(identifier, cur_time, add_ts_nr)))
    with open(output_directory / 'xgb_{0}_{1}{2}.pickle'.format(identifier, cur_time, add_ts_nr), mode = 'wb') as outfile:
      pickle.dump(clf, outfile)

    # if lrt:
    # pdf = matplotlib.backends.backend_pdf.PdfPages('/mnt/d/__thesis/data/_DATA/xgb_eval/xgb_lrt_{0}.pdf'.format(now_file()))
    # clf.save_model('/mnt/d/__thesis/data/_DATA/xgb_eval/xgb_lrt_{0}.model'.format(now_file()))

    # pdf_features = matplotlib.backends.backend_pdf.PdfPages('/root/thesis/data/_DATA/xgb_eval/rnd_ts/xgb_{0}_{1}{2}.features.pdf'.format(identifier, cur_time, add_ts_nr))
    # pdf_trees = matplotlib.backends.backend_pdf.PdfPages('/root/thesis/data/_DATA/xgb_eval/rnd_ts/xgb_{0}_{1}{2}.trees.pdf'.format(identifier, cur_time, add_ts_nr))
    # clf.save_model('/root/thesis/data/_DATA/xgb_eval/rnd_ts/xgb_{0}_{1}{2}.model'.format(identifier, cur_time, add_ts_nr))
    # with open('/root/thesis/data/_DATA/xgb_eval/rnd_ts/xgb_{0}_{1}{2}.pickle'.format(identifier, cur_time, add_ts_nr), mode = 'wb') as outfile:
    #   pickle.dump(clf, outfile)

    # else:
    #   # pdf = matplotlib.backends.backend_pdf.PdfPages('/mnt/d/__thesis/data/_DATA/xgb_eval/xgb_frt_{0}.pdf'.format(now_file()))
    #   # clf.save_model('/mnt/d/__thesis/data/_DATA/xgb_eval/xgb_frt_{0}.model'.format(now_file()))
    #   pdf_features = matplotlib.backends.backend_pdf.PdfPages('/root/thesis/data/_DATA/xgb_eval/rnd_ts/xgb_frt_{0}{1}.features.pdf'.format(cur_time, add_ts_nr))
    #   pdf_trees = matplotlib.backends.backend_pdf.PdfPages('/root/thesis/data/_DATA/xgb_eval/rnd_ts/xgb_frt_{0}{1}.trees.pdf'.format(cur_time, add_ts_nr))
    #   clf.save_model('/root/thesis/data/_DATA/xgb_eval/rnd_ts/xgb_frt_{0}{1}.model'.format(cur_time, add_ts_nr))
    #   with open('/root/thesis/data/_DATA/xgb_eval/rnd_ts/xgb_frt_{0}{1}.pickle'.format(cur_time, add_ts_nr), mode = 'wb') as outfile:
    #     pickle.dump(clf, outfile)

    plt.rcParams['figure.figsize'] = [15, 10] # [12.8, 9.6] # defaults * 2, was [15, 10]
    num = 0
    try:
      while True:
        fig = plt.figure(dpi = 256)
        axes = plt.subplot(111)
        xgb.plot_tree(clf, num_trees = num, ax = axes)
        pdf_trees.savefig(fig)
        plt.close(fig)
        num += 1
    except:
      pdf_trees.close()
    # https://github.com/dmlc/xgboost/blob/5465b73e7c13823225a1bc389b4defbdcbfaa6c0/python-package/xgboost/plotting.py#L14
    # (booster, ax=None, height=0.2, xlim=None, ylim=None, title='Feature importance', xlabel='F score', ylabel='Features', importance_type='weight', max_num_features=None, grid=True, show_values=True, **kwargs)
    # ax.barh(ylocs, values, align='center', height=height, **kwargs)
    # https://matplotlib.org/api/_as_gen/matplotlib.pyplot.barh.html
    # colors: https://matplotlib.org/2.0.2/api/colors_api.html
    # use lightgreen or lime
    fig = plt.figure(dpi = 256)
    axes = plt.subplot(111)
    xgb.plot_importance(clf, ax = axes, height = 0.5, color = 'lightgreen',  edgecolor = 'black', title = 'Feature Importance', xlabel = 'F-score', ylabel = 'Features', importance_type = 'weight', grid = False, show_values = True)
    pdf_features.savefig(fig)
    plt.close(fig)
    pdf_features.close()

  print('{0} - Training complete, starting predictions and calculations ...'.format(now()))

  y_pred_train = clf.predict(X_train)
  y_pred_test = clf.predict(X_test)

  sklearn_precision = metrics.precision_score(y_test, y_pred_test)

  if not own_model:
    X = X_train.append(X_test) # pd.DataFrame.append (NO list.append)
    y = y_train.copy()
    y.extend(y_test)
    cv_results = ms.cross_val_score(clf, X, y, cv = 10)
    y.clear()

  (sensitivity_train, specificity_train, precision_train, negative_predictive_value_train, false_negative_rate_train, false_positive_rate_train, false_discovery_rate_train, false_omission_rate_train, accuracy_train, f1_score_train, mcc_train, rates_train) = stats(y_train, y_pred_train, raw = True)
  (sensitivity_test, specificity_test, precision_test, negative_predictive_value_test, false_negative_rate_test, false_positive_rate_test, false_discovery_rate_test, false_omission_rate_test, accuracy_test, f1_score_test, mcc_test, rates_test) = stats(y_test, y_pred_test, raw = True)

  if not own_model:
    print('test             10-fold cv: {0}'.format(', '.join([str(val) for val in cv_results])))
    print('test         10-fold cv avg: {0}'.format(np.mean(cv_results, dtype = np.float64)))
  print('train                 rates: {0} TP, {1} FP, {2} TN, {3} FN'.format(*rates_train))
  print('test                  rates: {0} TP, {1} FP, {2} TN, {3} FN'.format(*rates_test))
  if best_score and best_iteration and best_ntree_limit:
    print('train        early stopping: {0} best_score, {1} best_iteration, {2} best_ntree_limit'.format(best_score, best_iteration, best_ntree_limit))
  print('test precision (clf, stats): {0}, {1}'.format(sklearn_precision, precision_test))
  print('test   sens, spec, npv, fnr: {0}, {1}, {2}, {3}'.format(sensitivity_test, specificity_test, negative_predictive_value_test, false_negative_rate_test))
  print('test fpr, fdr, for, acc, f1: {0}, {1}, {2}, {3}, {4}'.format(false_positive_rate_test, false_discovery_rate_test, false_omission_rate_test, accuracy_test, f1_score_test))
  print('train  mcc (sklearn, stats): {0}, {1}'.format(metrics.matthews_corrcoef(y_train, y_pred_train, sample_weight = train_weights), mcc_train))
  print('test   mcc (sklearn, stats): {0}, {1}'.format(metrics.matthews_corrcoef(y_test, y_pred_test, sample_weight = test_weights), mcc_test))

################################################################################
################################################################################
################################################################################
################################################################################
def print_cart_feature_importance(modelpath, features, feature_plot_path):
  """
  CART uses Mean Decrease in Impurity (MDI) or Gini importance as a measure for feature importance
  (The importance of a feature is computed as the (normalized) total reduction of the criterion brought by that feature)
  """
  # https://github.com/dmlc/xgboost/blob/master/python-package/xgboost/plotting.py
  with open(modelpath, mode = 'rb') as infile:
    model = pickle.load(infile)

  importances = zip(model.feature_importances_, features)
  feature_dict = { val: key for key, val in importances }

  pdf_features = matplotlib.backends.backend_pdf.PdfPages(feature_plot_path)
  fig = plt.figure(dpi = 256)
  axes = plt.subplot(111)
  xgb.plot_importance(feature_dict, ax = axes, height = 0.5, color = 'lightgreen',  edgecolor = 'black', title = 'Feature Importance', xlabel = 'F-score', ylabel = 'Features', importance_type = 'weight', grid = False, show_values = True)
  pdf_features.savefig(fig)
  plt.close(fig)
  pdf_features.close()
################################################################################
################################################################################

if __name__ == '__main__':
  # ALL available keys (not usable -> geo loc does not yield usable results)
  # feature_keys = [ 'hz4', 'hz6', 'hz_diff', 'hz4_R2', 'hz6_R2', 'raw_timestamp_diff', 'alpha4', 'alpha6', 'alphadiff', 'rsqr4', 'rsqr6', 'rsqrdiff', 'dynrange4', 'dynrange6', 'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel', 'spl_diff', 'spl_diff_scaled', 'ssh_keys_match', 'ssh_agents_match', 'geo4', 'geo6', 'geoloc_diff' ]
  # ALL usable keys
  # feature_keys = [ 'hz4', 'hz6', 'hz_diff', 'hz4_R2', 'hz6_R2', 'raw_timestamp_diff', 'alpha4', 'alpha6', 'alphadiff', 'rsqr4', 'rsqr6', 'rsqrdiff', 'dynrange4', 'dynrange6', 'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel', 'spl_diff', 'spl_diff_scaled', 'ssh_keys_match', 'ssh_agents_match', 'geoloc_diff' ]
  ##############################################################################

  # use this for xgb eval of features on FRT
  # feature_keys = [ 'hz_diff', 'hz_rsqrdiff', 'raw_timestamp_diff', 'alphadiff', 'rsqrdiff', 'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel', 'spl_diff', 'spl_diff_scaled' ]
  # use this for xgb eval of features on LRT AND FRT (LRT -> usually not enough timestamps for spline)
  # feature_keys = [ 'hz_diff', 'hz_rsqrdiff', 'raw_timestamp_diff', 'alphadiff', 'rsqrdiff', 'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel' ]
  # feature_keys = [ 'raw_timestamp_diff', 'hz_diff', 'dynrange_diff', 'dynrange_diff_rel' ] # to compare with CART
  # feature_keys = [ 'raw_timestamp_diff' ] # to compare with CART (only to check raw_timestamp_diff value used) # to compare with CART

  # DO NOT CHANGE ORDER
  feature_keys = {}
  feature_keys['full'] = [ 'hz_diff', 'hz_rsqrdiff', 'raw_timestamp_diff', 'alphadiff', 'rsqrdiff', 'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel', 'spl_diff', 'spl_diff_scaled' ]
  feature_keys['all'] = [ 'hz_diff', 'hz_rsqrdiff', 'raw_timestamp_diff', 'alphadiff', 'rsqrdiff', 'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel' ]
  feature_keys['four'] = [ 'raw_timestamp_diff', 'hz_diff', 'dynrange_diff', 'dynrange_diff_rel' ]
  feature_keys['one'] = [ 'raw_timestamp_diff' ]
  feature_keys['no_raw'] = [ 'hz_diff', 'hz_rsqrdiff', 'alphadiff', 'rsqrdiff', 'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel' ]
  # models:
  # CART: full [FRT only], all, four, one
  #  XGB: full [FRT only], all, four, one



  # LRT - set this to False if only raw_ts_diff or frequency related calculations necessary -> improves speed extremely
  const.SIB_LOWRT_CALC_ADDITIONAL_FEATURES = True
  const.SIB_LOWRT_CALC_ADDITIONAL_FEATURES_MIN_TIMESTAMPS = 8 # std: 8
  const.SIB_LOWRT_CALC_SPLINE = False
  const.SIB_LOWRT_MIN_TIMESTAMPS_FULL_CALC = 16 # std: 16

  # FRT - set calculations according to selected features
  const.SIB_FRT_CALC_ADDITIONAL_FEATURES = True
  const.SIB_FRT_CALC_SPLINE = False


  if len(sys.argv) < 2 or len(sys.argv) > 3:
    print("Usage: {0} <training_data_directory> [<predict_data_directory>]".format(sys.argv[0]))
    sys.exit(1)

  training_data_dir = pathlib.Path(sys.argv[1])
  try:
    predict_data_dir = pathlib.Path(sys.argv[2])
  except:
    predict_data_dir = None

  # unused
  tree_export_only = True

  if 'models' in str(training_data_dir.parent).lower():
    path_to_check = str(training_data_dir.name)
  else:
    path_to_check = training_data_dir.name if training_data_dir.is_dir() else training_data_dir.parent.name

  if '_lrt' in str(path_to_check).lower():
    low_runtime = True
    identifier = 'LRT'
  elif '_frt' in str(path_to_check).lower():
    low_runtime = False
    identifier = 'FRT'
  else:
    print('Could not determine full- or low-runtime!')
    sys.exit(0)

  # mainly for route inspection used
  if '/GT/' in str(training_data_dir).upper() or ('/ALEXA/' in str(training_data_dir).upper() and identifier == 'FRT'):
    no_subfolders = True
  else:
    no_subfolders = False


  # ----------------------------------------------------------------------------

  # print_cart_feature_importance(modelpath, features, feature_plot_path)
  # feature_keys['full'] # full, all, four, one
  # print_cart_feature_importance(training_data_dir, feature_keys['full'], predict_data_dir)
  # sys.exit(0)

  ##############################################################################
  ############################# ROUTE INSPECTION ###############################
  # print('{0} - Started'.format(now()))
  #
  # fkey = 'no_raw' # 'full' # 'all', 'no_raw'
  #
  # xgb_model_file = pathlib.Path(predict_data_dir / 'model_{0}_XGB_{1}.pickle'.format(identifier, fkey.replace('_', '-')))
  # cart_model_file_dropnan = pathlib.Path(predict_data_dir / 'model_{0}_CART_{1}_dropnan.pickle'.format(identifier, fkey))
  # cart_model_file_impute = pathlib.Path(predict_data_dir / 'model_{0}_CART_{1}_impute.pickle'.format(identifier, fkey))
  #
  # file_obj = xgb_model_file
  #
  # with open(file_obj, mode = 'rb') as infile:
  #   model = pickle.load(infile)
  #
  # if no_subfolders:
  #   edge_routers, intermediate_routers, edge_siblings, intermediate_siblings = evaluate_routers(training_data_dir, model, lrt = low_runtime, feature_keys = feature_keys[fkey])
  #
  #   print('{0} - Finished'.format(now()))
  #   print('                      Edge routers: {0}'.format(edge_routers))
  #   print('        Edge siblings/non-siblings: {0} / {1}'.format(edge_siblings, edge_routers - edge_siblings))
  #   print('              Intermediate routers: {0}'.format(intermediate_routers))
  #   print('Intermediate siblings/non-siblings: {0} / {1}'.format(intermediate_siblings, intermediate_routers - intermediate_siblings))
  #
  # else:
  #   evaluate_router_traces(training_data_dir, model, low_runtime, feature_keys[fkey])
  #
  # sys.exit(0)
  ##############################################################################


  ##############################################################################
  ############################ MODEL CONSTRUCTION ##############################
  ##############################################################################

  def drop_nan(X, y):
    X_joined = pd.DataFrame(X).join(pd.DataFrame(y, columns = ['y']))
    X_joined = X_joined.dropna()
    y = X_joined['y'].to_frame()
    X = X_joined.drop(['y'], axis = 1) # 1 -> column
    y = y.values.reshape(-1,).tolist()
    return X, y

  def impute(X, y):
    X = imp.SimpleImputer(missing_values = np.nan, strategy = 'mean').fit_transform(X, y)
    return X, y

  ##############################################################################
  # SINGLE MODEL CONSTRUCTION
  ##############################################################################
  # key = 'all'
  # fkey = 'all'
  # limit_nr_timestamps = None # 10, 50, 100, 150, 200
  #
  # sibling_features = construct_evaluated_features_to_train(training_data_dir, lrt = low_runtime, feature_keys = feature_keys[fkey], split_nlnog_ripe = True, batch_size = 5000, timestamp_limit = limit_nr_timestamps)
  #
  # construct_model(sibling_features, tree.DecisionTreeClassifier, lrt = low_runtime, feature_keys = feature_keys[fkey], missing_values_handler = drop_nan, model_file_name = predict_data_dir / 'model_{0}_CART_{1}_dropnan.pickle'.format(identifier, key))
  # construct_model(sibling_features, tree.DecisionTreeClassifier, lrt = low_runtime, feature_keys = feature_keys[fkey], missing_values_handler = impute, model_file_name = predict_data_dir / 'model_{0}_CART_{1}_impute.pickle'.format(identifier, key))
  # construct_model(sibling_features, xgb.XGBClassifier, lrt = low_runtime, feature_keys = feature_keys[fkey], missing_values_handler = None, model_file_name = predict_data_dir / 'model_{0}_XGB_{1}.pickle'.format(identifier, key), model_fimportance_fname = predict_data_dir / 'model_{0}_XGB_{1}.features.pdf'.format(identifier, key))
  #
  # sys.exit(0)
  ##############################################################################
  #                         GENERAL MODEL CONSTRUCTION                         #
  ##############################################################################
  # if low_runtime:
  #   sibling_features = construct_evaluated_features_to_train(training_data_dir, lrt = low_runtime, feature_keys = feature_keys['all'], split_nlnog_ripe = True, batch_size = 5000)
  #   del feature_keys['full']
  # else:
  #   sibling_features = construct_evaluated_features_to_train(training_data_dir, lrt = low_runtime, feature_keys = feature_keys['full'], split_nlnog_ripe = True, batch_size = 5000)
  #
  #
  # for key, value in feature_keys.items():
  #   print('{0} - {1}'.format(now(), key))
  #   construct_model(sibling_features, tree.DecisionTreeClassifier, lrt = low_runtime, feature_keys = value, missing_values_handler = drop_nan, model_file_name = predict_data_dir / 'model_{0}_CART_{1}_dropnan.pickle'.format(identifier, key))
  #   construct_model(sibling_features, tree.DecisionTreeClassifier, lrt = low_runtime, feature_keys = value, missing_values_handler = impute, model_file_name = predict_data_dir / 'model_{0}_CART_{1}_impute.pickle'.format(identifier, key))
  #
  #   construct_model(sibling_features, xgb.XGBClassifier, lrt = low_runtime, feature_keys = value, missing_values_handler = None, model_file_name = predict_data_dir / 'model_{0}_XGB_{1}.pickle'.format(identifier, key))
  #
  # sys.exit(0)
  ##############################################################################
  ##############################################################################
  ####            UNUSED          MODEL TESTING           UNUSED            ####
  ##############################################################################

  # fkey = 'no_raw'
  # limit_timestamps = None # 10 # None
  #
  # print('{0}/{1}'.format(training_data_dir.parent.name, training_data_dir.name))
  # print('feature_keys = {0}'.format(feature_keys[fkey]))
  # print()
  # print('{0} - Started'.format(now()))
  #
  # X, y = construct_evaluated_features_to_train(training_data_dir, lrt = low_runtime, feature_keys = feature_keys[fkey], split_nlnog_ripe = True, batch_size = 5000, timestamp_limit = None)
  #
  # model = ProposedModel('/root/thesis/data/_DATA/MODELS/rndts_models/model_{0}_XGB_{1}.pickle'.format(identifier, fkey.replace('_', '-')))
  #
  # y_pred = model.predict(X)
  #
  # (sensitivity, specificity, precision, negative_predictive_value, false_negative_rate, false_positive_rate, false_discovery_rate, false_omission_rate, accuracy, f1_score, mcc, rates) = stats(y, y_pred, raw = True)
  #
  # print('test                  rates: {0} TP, {1} FP, {2} TN, {3} FN'.format(*rates))
  # print('test      precision (stats): {0}'.format(precision))
  # print('test   sens, spec, npv, fnr: {0}, {1}, {2}, {3}'.format(sensitivity, specificity, negative_predictive_value, false_negative_rate))
  # print('test fpr, fdr, for, acc, f1: {0}, {1}, {2}, {3}, {4}'.format(false_positive_rate, false_discovery_rate, false_omission_rate, accuracy, f1_score))
  # print('test   mcc (sklearn, stats): {0}, {1}'.format(metrics.matthews_corrcoef(y, y_pred, sample_weight = None), mcc))
  #
  # print()
  # print('{0} - Finished'.format(now()))
  # print()
  # print('-'*80)
  # print()
  #
  # sys.exit(0)

  ##############################################################################
  ####                       GENERAL MODEL EVALUATION                       ####
  ##############################################################################

  test_sizes = [ 0.1, 0.33, 0.66, 0.9 ]
  fkey = 'all' # 'no_raw'
  limit_timestamps = None # 10 # None

  for ts in test_sizes:

    print('{0}/{1} - test_size = {2}'.format(training_data_dir.parent.name, training_data_dir.name, ts))
    print('feature_keys = {0}'.format(feature_keys[fkey]))
    print()
    print('{0} - Started'.format(now()))
    xgb_evaluation(training_data_dir, output_directory = None, own_model = True, lrt = low_runtime, test_size = ts, feature_keys = feature_keys[fkey], mcc_weights = False, batch_size = 5000, split_nlnog_ripe = True, print_tree = False, limit_nr_timestamps = limit_timestamps)
    # xgb_evaluation(training_data_dir, output_directory = predict_data_dir, own_model = False, lrt = low_runtime, test_size = ts, feature_keys = feature_keys[fkey], mcc_weights = False, batch_size = 5000, split_nlnog_ripe = True, print_tree = True, limit_nr_timestamps = limit_timestamps)
    # scheitle_evaluation(training_data_dir, lrt = low_runtime, test_size = ts, feature_keys = feature_keys, mcc_weights = False, batch_size = 5000, split_nlnog_ripe = True, print_tree = True)
    print('{0} - Finished'.format(now()))
    print()
    print('-'*80)
    print()

  sys.exit(0)

  # ----------------------------------------------------------------------------
################################################################################
################################# OLD TESTS ####################################
################################################################################

# print('{0} - started test data construction'.format(now()))
  # # void_siblings 272516, nlnog_siblings 168510, ripe_siblings 104006
  # valid_sibs, void_sibs, len_void, len_nlnog, len_ripe, len_unknown = construct_test_data(training_data_dir, lrt = True)
  # len_valid_sibs = len(valid_sibs)
  # max_void_sibs = len_void # len_valid_sibs * 100 ## 50 # ~ 36k ## 100 # ~ 72k
  # batch_size = 1000
  # # select random samples out of the void_sibs
  # sampled_voids = random.sample(void_sibs, max_void_sibs)
  # # del(void_sibs)
  # # gc.collect()
  # print('{0} - finished test data construction'.format(now()))
  #
  #
  # # print('{0} - started geoloc assignment'.format(now()))
  # # # determine geolocation matches
  # # geo = libgeo.Geo()
  # # for sib in valid_sibs:
  # #   sib.geoloc_diff = sib.calc_geolocation_differ(geoloc_obj = geo)
  # # for sib in sampled_voids:
  # #   sib.geoloc_diff = sib.calc_geolocation_differ(geoloc_obj = geo)
  # # print('{0} - finished geoloc assignment'.format(now()))
  #
  #
  # print('{0} - started feature construction'.format(now()))
  # X = []
  # X.extend(construct_features(valid_sibs, keys = feature_keys))
  #
  # voids = list(libtools.split_list(sampled_voids, batch_size))
  # for vlist in voids:
  #   X.extend(construct_features(vlist, keys = feature_keys))
  #
  # y = [1 for _ in range(len_valid_sibs)]
  # y.extend([0 for _ in range(max_void_sibs)])
  # print('{0} - finished feature construction'.format(now()))
  #
  #
  # print('{0} - started feature selection'.format(now()))
  # # vectorize features
  # v = fe.DictVectorizer()
  # X = v.fit_transform(X)
  # # print(v.get_feature_names())
  # # print(X.shape)
  #
  # # may falsify data if filled with mean values ?!
  # X = imp.SimpleImputer(missing_values = np.nan, strategy = 'mean').fit_transform(X, y)
  #
  # # # feature selection # https://scikit-learn.org/stable/modules/feature_selection.html#tree-based-feature-selection
  # # fselector = select_features(X, y, selector = fs.SelectKBest, score_func = fs.mutual_info_classif, transform = False, k = 4)
  # # # reduce vectorized features to selected
  # # v.restrict(fselector.get_support())
  # # # ['dynrange_diff_rel', 'hz_diff', 'raw_timestamp_diff', 'rsqrdiff'] impute by mean, SelectKBest (k = 4) -> mutual_info_classif
  # # print(v.get_feature_names())
  # # X = fselector.transform(X)
  # # print(X.shape)
  # print('{0} - finished feature selection'.format(now()))
  #
  # print('{0} - started model fitting and validation'.format(now()))
  # X_train, X_test, y_train, y_test = ms.train_test_split(X, y, test_size = 0.75, random_state = 42)
  # # print(X_train.shape, X_test.shape)
  # #
  # # # model fitting # https://stackoverflow.com/a/41853264
  # # # from sklearn.neighbors import KNeighborsClassifier
  #
  # clf = tree.DecisionTreeClassifier(max_depth = 10)
  # clf.fit(X_train, y_train)
  #
  # # # 1st run -> 2 * len_valid_sibs; DecisionTreeClassifier(max_depth = 10)
  # # # [0.95945946 0.97260274 0.98630137 0.98630137 0.98630137 0.97260274 0.98611111 0.98611111 0.95833333 0.94444444]
  # # # 0.9669876203576341
  # # # 2nd run -> 100 * len_valid_sibs
  # # # [0.99816101 0.99938688 0.99918251 0.99897813 0.99897813 0.99877376 0.99959125 0.99897813 0.99836468 0.99938675]
  # # # 0.9986306689284473
  # # print(ms.cross_val_score(clf, X_test, y_test, cv = 5)) # used 10 before
  # # print(clf.score(X_test, y_test))
  # # # exit(0)
  #
  # print('{0} - started model fitting with all available data'.format(now()))
  # clf = tree.DecisionTreeClassifier(max_depth = 10)
  # clf.fit(X, y)
  # print('{0} - finished model fitting with all available data'.format(now()))
  # # https://scikit-learn.org/stable/modules/generated/sklearn.tree.export_graphviz.html
  # tree.export_graphviz(clf, out_file = '/root/thesis/data/_DATA/{0}_ml_decision_tree.dot'.format(now_file()), feature_names = v.get_feature_names(), filled = True, rounded = True) # proportion = True
  #
  # if tree_export_only:
  #   sys.exit(0)
  #
  # print('{0} - started loading prediction data (including geolocation)'.format(now()))
  # trace_sibs = list(load_data(predict_data_dir, 't', lrt = True).values()) # returns dict -> transform to list
  # # print('{0} - started geoloc assignment'.format(now())) # not necessary since no feature key for geo related tasks is used
  # # # determine geolocation matches
  # # for sib in trace_sibs:
  # #   sib.geoloc_diff = sib.calc_geolocation_differ(geoloc_obj = geo)
  # # print('{0} - finished loading prediction data'.format(now()))
  #
  # print('{0} - started processing prediction data (feature construction, removing candidates without required keys)'.format(now()))
  # # ['dynrange_diff_rel', 'hz_diff', 'raw_timestamp_diff', 'rsqrdiff']
  # # ['dynrange_diff', 'hz_diff', 'raw_timestamp_diff', 'rsqrdiff']
  # # ['dynrange_diff', 'hz_diff', 'raw_timestamp_diff', 'rsqrdiff']
  # # ['dynrange_diff', 'dynrange_diff_rel', 'hz_diff', 'raw_timestamp_diff']
  # # ['dynrange_diff', 'dynrange_diff_rel', 'hz_diff', 'raw_timestamp_diff']
  # # ['alphadiff', 'dynrange_diff_rel', 'hz_diff', 'raw_timestamp_diff']
  # # ['alphadiff', 'dynrange_diff_rel', 'hz_diff', 'raw_timestamp_diff']
  # #
  # # => [ 'raw_timestamp_diff', 'hz_diff', 'dynrange_diff_rel', 'dynrange_diff' ]
  # fkeys = [ 'raw_timestamp_diff', 'hz_diff', 'dynrange_diff', 'dynrange_diff_rel' ]
  # # TODO: do feature selection based on 10 runs where precision >99% and use the X most often selected features by the SelectKBest and score function
  #
  # X = []
  # invalid = []
  # sibs = list(libtools.split_list(trace_sibs, batch_size))
  # for s in sibs:
  #   sfeatures, sinvalid = construct_features(s, keys = fkeys, ignore_invalid = True, return_invalid = True)
  #   X.extend(sfeatures)
  #   invalid.extend(sinvalid)
  #   print('{0} - processed batch'.format(now()))
  #
  # print('{0} - Number of unusable candidate pairs: {1} of {2}'.format(now(), len(invalid), len(trace_sibs)))
  # invalid.clear()
  #
  # if not X:
  #   print('{0} - No predictable data available, exiting ...'.format(now()))
  #   exit(0)
  #
  # # vectorize features
  # v = fe.DictVectorizer()
  # X = v.fit_transform(X)
  #
  # print('{0} - finished prediction data processing'.format(now()))
  #
  # print('{0} - started prediction'.format(now()))
  # y_predicted = clf.predict(X)
  # print('{0} - finished prediction'.format(now()))
  #
  # current_time = now_file()
  # # tree.export_graphviz(clf, out_file = '/root/thesis/data/_DATA/{0}_ml_decision_tree.dot'.format(current_time))
  #
  # print('{0} - writing results to file'.format(now()))
  # with open('/root/thesis/data/_DATA/{0}_ml_predictions.txt'.format(current_time), mode = 'w') as outfile:
  #   outfile.write('{0};prediction\n'.format(';'.join(v.get_feature_names())))
  #   for i in range(X.get_shape()[0]):
  #     row = ';'.join([ str(val) for val in X.A[i]])
  #     try:
  #       outfile.write('{0};{1}\n'.format(row, y_predicted[i]))
  #     except IndexError:
  #       outfile.write('{0};?\n'.format(row))
  #
  # print('{0} - finished'.format(now()))
  #
  #
  #
  # sys.exit(0)

#
# TODO: => due to calculation times evaluate siblings on the fly while loading features
# siblings -> list of siblings
# -> calculate results on the fly
# -> get_features()
# -> plot (if full runtime) -> use pdfpages object and create function to submit to SiblingCandidate.plot()
# -> append to result file -> use own function in evaluation.py to append to a file

# TODO: INITIAL NODES
#
# *) Load data and perform calculations
# *) Construct train and test sets
# *) Feature selection
# *) Performance evaluation
