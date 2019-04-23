#!/usr/bin/env python3
#
# xgb_print_features.py
#
# (c) 2019 Marco Starke
#

import sys
import pickle
import numpy as np
import xgboost as xgb
import matplotlib.backends.backend_pdf as backend_pdf
import matplotlib.pyplot as plt
from mpl_toolkits.axes_grid1 import make_axes_locatable # append axes
import matplotlib.gridspec as grd # own grids for axes
################################################################################

edge_s_lrt = [ 134, 1283, 2429 ]
edge_n_lrt = [ 557, 7066, 24585 ]
core_s_lrt = [ 75, 645, 1366 ]
core_n_lrt = [ 604, 5745, 13749 ]

edge_s_frt = [ 151, 1233, 4942 ]
edge_n_frt = [ 450, 6150, 22679 ]
core_s_frt = [ 103, 641, 1160 ]
core_n_frt = [ 484, 3698, 7700 ]

# plot_net_eval('net_frt_eval.pdf', (edge_s_frt, edge_n_frt, core_s_frt, core_n_frt), xlabel = 'Full-Runtime Data Sets', ylabel = 'Number of Identified IP Pairs')
# plot_net_eval('net_lrt_eval.pdf', (edge_s_lrt, edge_n_lrt, core_s_lrt, core_n_lrt), xlabel = 'Low-Runtime Data Sets', ylabel = 'Number of Identified IP Pairs')

def plot_net_eval(filename, datasets, figsize = [11, 6], xlabel = None, ylabel = None, rotation = 'horizontal', barwidth = 0.7, xlabelpad = 10, ylabelpad = 12):
  yvals = np.array(datasets)

  xticklabels = [ 'Ground Truth', 'Alexa', 'Cisco' ]
  datalabel = [ 'Edge Siblings', 'Edge Non-Siblings', 'Core Siblings', 'Core Non-Siblings' ]
  # colors = [ 'yellowgreen', 'greenyellow', 'burlywood', 'bisque' ]
  colors = [ 'cornflowerblue', 'greenyellow', 'lightcoral', 'bisque' ]

  border = 600
  borderthreshold = 50

  xval = np.array([4 * i for i in range(len(xticklabels))]) # sclaing -> increase space on the x axis between ticks

  pdf = backend_pdf.PdfPages(filename)

  plt.rcParams['figure.figsize'] = figsize
  fig = plt.figure(dpi = 256)
  gs = grd.GridSpec(2, 1, wspace = 0.0, hspace = 0.0, height_ratios=[2.0/3, 1.0/3])

  axlog = plt.subplot(gs[0])
  axlin = plt.subplot(gs[1])

  width = barwidth

  axlin.set_yscale('linear')
  axlin.set_ylim((0, border))
  axlin.spines['top'].set_visible(False)
  axlin.set_xticks(xval + width + 0.5 * width) # set xticks
  axlin.set_xticklabels(xticklabels) # set xticklabels
  # ax.yaxis.set_major_locator(plt.MaxNLocator(4))

  axlog.set_yscale('log')
  axlog.set_ylim((border, 30000))
  axlog.set_xticks([]) # just to be sure ...
  axlog.set_xticklabels([]) # just to be sure ...
  axlog.spines['bottom'].set_visible(False)

  for i in range(len(yvals)):
    axlin.bar(xval + i * width, width = width, height = yvals[i], color = colors[i], edgecolor = 'black', label = datalabel[i])
    axlog.bar(xval + i * width, width = width, height = yvals[i], color = colors[i], edgecolor = 'black', label = datalabel[i])
    for x, y in zip(xval, yvals[i]):
      va = 'top'
      if y < border + borderthreshold:
        if y > border + 5:
          y_txt_offset = -int(0.08 * y) # special case at border: >600, <700  was: 0.08
        else:
          y_txt_offset = -int(0.05 * y) # take % of the yval and use it as y_txt_offset
        if y < 200:
          y_txt_offset = 25 # write text above bar in this case
          va = 'bottom'
        axlin.text(x + i * width, y + y_txt_offset, str(y), ha = 'center', va = va, rotation = 'vertical')
        va = 'top'
      else:
        y_txt_offset = -int(0.08 * y)
        axlog.text(x + i * width, y + y_txt_offset, str(y), ha = 'center', va = 'top', rotation = 'vertical')

  box = axlog.get_position()
  axlog.set_position([ box.x0, box.y0 + box.height * 0.1, box.width, box.height * 0.9 ])
  axlog.legend(loc = 'lower left', bbox_to_anchor = (0, 1.02, 1, 0.2), fancybox = True, shadow = False, ncol = 4, mode = 'expand')

  # add a big axis, hide frame # https://stackoverflow.com/a/53172335
  fig.add_subplot(111, frameon = False)
  # hide tick and tick label of the big axis
  plt.tick_params(labelcolor = 'none', top = False, bottom = False, left = False, right = False)
  if xlabel is not None:
    plt.xlabel(xlabel, labelpad = xlabelpad) # increase distance between ylabel and axis # 'Low-Runtime Data Sets'
  if ylabel is not None: # 'Number of Network Nodes'
    plt.ylabel(ylabel, labelpad = ylabelpad) # increase distance between ylabel and axis

  plt.subplots_adjust(bottom = 0.1, top = 0.92, left = 0.08, right = 0.98)

  pdf.savefig(fig)
  plt.close(fig)
  pdf.close()



#####################################################################################

edge_lrt = [ 691, 8349, 27014 ]
core_lrt = [ 679, 6390, 15115 ]

edge_frt = [ 601, 7383, 27621 ]
core_frt = [ 587, 4339, 8860 ]

def plot_router_cmp(filename, datasets, figsize = [5, 6], xlabel = None, ylabel = None, rotation = 'horizontal', barwidth = 1.2, xlabelpad = 10, ylabelpad = 12):
  yvals = np.array(datasets)

  xticklabels = [ 'Ground Truth', 'Alexa', 'Cisco' ]
  datalabel = [ 'Edge Node Pairs', 'Core Node Pairs' ]

  xval = np.array([4 * i for i in range(len(xticklabels))]) # scale if necessary

  pdf = backend_pdf.PdfPages(filename)

  plt.rcParams['figure.figsize'] = figsize
  fig = plt.figure(dpi = 256)

  gs = grd.GridSpec(2, 1, wspace = 0.0, hspace = 0.0, height_ratios=[2.0/3, 1.0/3])

  axlog = plt.subplot(gs[0])
  axlin = plt.subplot(gs[1])

  width = barwidth

  axlin.set_yscale('linear')
  axlin.set_ylim((0, 800))
  axlin.spines['top'].set_visible(False)
  axlin.set_xticks(xval + width / 2.0) # set xticks
  axlin.set_xticklabels(xticklabels) # set xticklabels
  # ax.yaxis.set_major_locator(plt.MaxNLocator(4))

  axlog.set_yscale('log')
  axlog.set_ylim((800, 30000))
  axlog.set_xticks([]) # just to be sure ...
  axlog.set_xticklabels([]) # just to be sure ...
  axlog.spines['bottom'].set_visible(False)

  colors = [ 'olivedrab', 'sandybrown' ] # instead of darkolivegreen -> olive or olivedrab
  for i in range(len(yvals)):
    axlin.bar(xval + i * width, width = width, height = yvals[i], color = colors[i], edgecolor = 'black', label = datalabel[i])
    axlog.bar(xval + i * width, width = width, height = yvals[i], color = colors[i], edgecolor = 'black', label = datalabel[i])
    for x, y in zip(xval, yvals[i]):
      if y < 1000:
        y_txt_offset = -int(0.05 * y) # take % of the yval and use it as y_txt_offset
      else:
        y_txt_offset = -int(0.08 * y)
      axlin.text(x + i * width, y + y_txt_offset, str(y), ha = 'center', va = 'top', rotation = 'vertical')
      axlog.text(x + i * width, y + y_txt_offset, str(y), ha = 'center', va = 'top', rotation = 'vertical')

  box = axlog.get_position()
  axlog.set_position([ box.x0, box.y0 + box.height * 0.1, box.width, box.height * 0.9 ])
  axlog.legend(loc = 'lower left', bbox_to_anchor = (0, 1.02, 1, 0.2), fancybox = True, shadow = False, ncol = 2, mode = 'expand')

  # add a big axis, hide frame # https://stackoverflow.com/a/53172335
  fig.add_subplot(111, frameon = False)
  # hide tick and tick label of the big axis
  plt.tick_params(labelcolor = 'none', top = False, bottom = False, left = False, right = False)
  if xlabel is not None:
    plt.xlabel(xlabel, labelpad = xlabelpad) # increase distance between ylabel and axis # 'Low-Runtime Data Sets'
  if ylabel is not None: # 'Number of Network Nodes'
    plt.ylabel(ylabel, labelpad = ylabelpad) # increase distance between ylabel and axis

  plt.subplots_adjust(bottom = 0.1, top = 0.92, left = 0.14, right = 0.95)
  # fig.tight_layout() # does not work here

  pdf.savefig(fig)
  plt.close(fig)
  pdf.close()
################################################################################




#####################################################
# CMP FRT & LRT no-raw data on all available GT nodes
#####################################################

##### complete model mcc and prec data
fullmccf = [ 0.9929505260910099, 0.9713261153947516, 0.9530328442983413, 0.7209237926707617 ]
fullmccl = [ 0.9647723084878773, 0.9726729446678353, 0.9727211263068622, 0.9446574264058993 ]

fullprecf = [ 1.0, 0.9558232931726908, 0.9239766081871345, 0.5308641975308642 ]
fullprecl = [ 1.0, 1.0, 1.0, 0.9441087613293051 ]

#############################################

# randomized TS model only data

cvfvals = [ 0.9979545242754636, 0.9970392156862745, 0.9980675877520537, 0.9980476491671938 ]
cvlvals = [ 0.9655594673197612, 0.9449164483037826, 0.9480193264434795, 0.9671226449956458 ]
# cvf = np.mean(cvfvals)
# cvl = np.mean(cvlvals)

mccf = [ 0.8728715609439696, 0.9637997471501198, 0.8809436849548193, 0.5106712136423351 ]
mccl = [ 0.0, 0.12678904397193233, 0.2126032259786609, 0.23079742392048974 ]

precf = [ 1.0, 1.0, 0.7837837837837838, 0.43103448275862066 ]
precl = [ 0.0, 0.3333333333333333, 0.21052631578947367, 0.1360544217687075 ]

accf = [ 0.96, 0.9955555555555555, 0.990487514863258, 0.9690992767915845 ]
accl = [ 0.8, 0.923469387755102, 0.9362244897959183, 0.899584487534626 ]


def print_frt_lrt_cmp(filename, datasets, figsize = [4.5, 5.5], ylabel = None, rotation = 'horizontal', round_digits = None):

  y_one, y_two = datasets

  if round_digits is not None:
    y_one = [ round(x, round_digits) for x in y_one ]
    y_two = [ round(x, round_digits) for x in y_two ]

  xlabel = ['0.1', '0.33', '0.66', '0.9']
  xval = np.arange(len(xlabel))

  pdf = backend_pdf.PdfPages(filename)

  plt.rcParams['figure.figsize'] = figsize
  fig = plt.figure(dpi = 256)
  ax = plt.subplot(111)

  width = 0.4

  ax.bar(xval, width = width, height = y_one, color = 'lightgreen', edgecolor = 'black', label = 'Full-Runtime')
  ax.bar(xval + width, width = width, height = y_two, color = 'peachpuff', edgecolor = 'black', label = 'Low-Runtime') # lightsteelblue, lightskyblue
  ax.set_ylim(bottom = 0.0, top = 1.0)
  ax.set_xlabel('Test Size')
  if ylabel is not None:
    ax.set_ylabel(ylabel)
    if ylabel == 'Precision':
      y_txt_offset = -0.035
    elif ylabel == 'MCC':
      y_txt_offset = -0.035 # 0.01
    else:
      y_txt_offset = 0.5

  # y_txt_offset = -0.035 # 0.01 for mcc values, -0.035 for prec values
  for x, y in zip(xval, [ round(y, 2) for y in y_one ]):
    if y < 0.05:
      old_offset = y_txt_offset
      y_txt_offset = 0.01
    ax.text(x, y + y_txt_offset, str(y), ha = 'center', rotation = 'horizontal')
    if y < 0.05:
      y_txt_offset = old_offset

  for x, y in zip(xval, [ round(y, 2) for y in y_two ]):
    if y < 0.05:
      old_offset = y_txt_offset
      y_txt_offset = 0.01
    ax.text(x + width, y + y_txt_offset, str(y), ha = 'center', rotation = 'horizontal')
    if y < 0.05:
      y_txt_offset = old_offset

  box = ax.get_position()
  ax.set_position([ box.x0, box.y0 + box.height * 0.1, box.width, box.height * 0.9 ])
  ax.legend(loc = 'lower left', bbox_to_anchor = (0, 1.02, 1, 0.2), fancybox = True, shadow = False, ncol = 2, mode = 'expand')

  plt.xticks(xval + width / 2.0, xlabel, rotation = rotation) # {angle in degrees, 'vertical', 'horizontal'}
  # plt.margins(0.2) # margin between bars and axis
  plt.subplots_adjust(bottom = 0.1, top = 0.95, left = 0.13, right = 0.95)
  fig.tight_layout()

  pdf.savefig(fig)
  plt.close(fig)
  pdf.close()

################################################################################

# colors: lemonchiffon, peachpuff, plum, lightgreen
# colors for 2 bars: peachpuff, lightgreen

# RND TS - #TS comparison data

ts10 = [ 1.0, 1.0, 1.0, 0.9180097687300888 ]
ts50 = [ 0.8728715609439696, 0.8881060715737716, 0.7763696186594595, 0.5603503922154651 ]
ts100 = [ 1.0, 0.8501838417622961, 0.9161494749755463, 0.6664342773818541 ]
ts150 = [ 0.8728715609439696, 0.9285714285714286, 0.9068897284630788, 0.6284117406521569 ]
ts200 = [ 0.8728715609439696, 0.9637997471501198, 0.9351250581921513, 0.5798188947779471 ]

def plot_nr_ts_cmp(filename, datasets, figsize = [11, 6], ylabel = None, rotation = 'horizontal'):
  # plot_nr_ts_cmp('xgb_rnd_ts_cmp.pdf', (ts10, ts50, ts100, ts150, ts200), figsize = [11, 6], ylabel = 'MCC')
  # yts10, yts50, yts100, yts150, yts200 = datasets
  data = np.array(datasets) # get column with [:,x]

  # legendlabel = ['0.1', '0.33', '0.66', '0.9']
  legendlabel = ['Test Size 0.1', 'Test Size 0.33', 'Test Size 0.66', 'Test Size 0.9']
  xlabel = ['10', '50', '100', '150', '200'] # ['200', '150', '100', '50', '10']
  xval = np.array([4 * i for i in range(len(xlabel))]) # sclaing -> increase space on the x axis between ticks

  pdf = backend_pdf.PdfPages(filename)

  plt.rcParams['figure.figsize'] = figsize
  fig = plt.figure(dpi = 256)
  ax = plt.subplot(111)

  width = 0.7

  colors = list(reversed([ 'lightgreen', 'plum', 'peachpuff', 'lemonchiffon' ]))
  for i in range(len(data[0])):
    ax.bar(xval + i * width, width = width, height = data[:,i], color = colors[i], edgecolor = 'black', label = legendlabel[i])
    for x, y in zip(xval + i * width, [ round(y, 2) for y in data[:,i] ]):
      ax.text(x, y - 0.035, str(y), ha = 'center', rotation = 'horizontal')

  ax.set_ylim(bottom = 0.0, top = 1.0)
  ax.set_xlabel('Number of Timestamps')
  if ylabel is not None:
    ax.set_ylabel(ylabel)

  # plt.legend(loc = 'lower right') # best
  # https://stackoverflow.com/questions/4700614/how-to-put-the-legend-out-of-the-plot
  box = ax.get_position()
  ax.set_position([ box.x0, box.y0 + box.height * 0.1, box.width, box.height * 0.9 ])
  # Put a legend below current axis
  ax.legend(loc = 'lower left', bbox_to_anchor = (0, 1.02, 1, 0.2), fancybox = True, shadow = False, ncol = 4, mode = 'expand')
  # plt.margins(0.5) # margin between bars and axis
  plt.xticks(xval + width + width / 2.0, xlabel, rotation = rotation) # {angle in degrees, 'vertical', 'horizontal'}
  # ax.tick_params(axis = 'x', which = 'major', width = 1) # increase tick thickness
  plt.subplots_adjust(bottom = 0.1, top = 0.95, left = 0.13, right = 0.95) # use in combination with tight_layout to ensure xlabel is shown
  fig.tight_layout() # fit canvas to actually necessary size

  pdf.savefig(fig)
  plt.close(fig)
  pdf.close()

################################################################################



# importance_type =
# * 'weight': the number of times a feature is used to split the data across all trees. -> F-Score
# * 'gain': the average gain across all splits the feature is used in.
# * 'cover': the average coverage across all splits the feature is used in.
# * 'total_gain': the total gain across all splits the feature is used in.
# * 'total_cover': the total coverage across all splits the feature is used in.

# SCORES XGB_LRT [0.1, 0.33, 0.66, 0.9]
lrt_1 = {'raw_ts_diff': 325, 'rng_avg': 258, 'hz_rsqrdiff': 229, 'alphadiff': 179, 'hz_diff': 218, 'rng_diff': 117, 'rng_reldiff': 129, 'rsqrdiff': 115}
lrt_3 = {'raw_ts_diff': 316, 'rng_avg': 228, 'hz_rsqrdiff': 217, 'rsqrdiff': 120, 'hz_diff': 192, 'rng_diff': 115, 'rng_reldiff': 95, 'alphadiff': 140}
lrt_6 = {'raw_ts_diff': 244, 'rng_avg': 101, 'hz_rsqrdiff': 157, 'hz_diff': 136, 'rng_diff': 61, 'rng_reldiff': 68, 'alphadiff': 97, 'rsqrdiff': 67}
lrt_9 = {'raw_ts_diff': 161, 'rng_diff': 79, 'hz_rsqrdiff': 64, 'alphadiff': 54, 'rng_avg': 22, 'hz_diff': 89, 'rsqrdiff': 39, 'rng_reldiff': 35}
# SCORES XGB_FRT [0.1, 0.33, 0.66, 0.9]
frt_1 = {'raw_ts_diff': 189, 'rng_avg': 256, 'alphadiff': 115, 'hz_diff': 146, 'rsqrdiff': 40, 'rng_diff': 38, 'rng_reldiff': 47, 'hz_rsqrdiff': 48}
frt_3 = {'raw_ts_diff': 171, 'rng_avg': 213, 'alphadiff': 97, 'hz_diff': 126, 'rsqrdiff': 26, 'rng_reldiff': 47, 'rng_diff': 36, 'hz_rsqrdiff': 30}
frt_6 = {'raw_ts_diff': 130, 'rng_avg': 107, 'alphadiff': 94, 'rng_diff': 22, 'hz_diff': 76, 'rsqrdiff': 25, 'hz_rsqrdiff': 20, 'rng_reldiff': 15}
frt_9 = {'raw_ts_diff': 93, 'hz_diff': 68, 'alphadiff': 79, 'rng_avg': 59, 'rng_reldiff': 29, 'rsqrdiff': 47, 'rng_diff': 29, 'hz_rsqrdiff': 9}

printmap_lrt = { 'xgb_lrt_all_1_features.pdf': ('Low-Runtime Test Size 0.1', lrt_1), 'xgb_lrt_all_3_features.pdf': ('Low-Runtime Test Size 0.33', lrt_3), 'xgb_lrt_all_6_features.pdf': ('Low-Runtime Test Size 0.66', lrt_6), 'xgb_lrt_all_9_features.pdf': ('Low-Runtime Test Size 0.9', lrt_9) }
printmap_frt = { 'xgb_frt_all_1_features.pdf': ('Full-Runtime Test Size 0.1', frt_1), 'xgb_frt_all_3_features.pdf': ('Full-Runtime Test Size 0.33', frt_3), 'xgb_frt_all_6_features.pdf': ('Full-Runtime Test Size 0.66', frt_6), 'xgb_frt_all_9_features.pdf': ('Full-Runtime Test Size 0.9', frt_9) }

def plot_all_feature_scores(no_title = True):
  for fname, titledata in printmap_frt.items():
    title, data = titledata
    if no_title:
      title = None
    bar_plot(fname, data, ylabel = 'F-Score', title = title, figsize = [5, 5])
  for fname, titledata in printmap_lrt.items():
    title, data = titledata
    if no_title:
      title = None
    bar_plot(fname, data, ylabel = 'F-Score', title = title, figsize = [5, 5])


def bar_plot(output_file, data, figsize = [5, 6], title = None, xlabel = None, ylabel = None, rotation = 45, show_values = True, show_values_yoffset = 1):
  """
  data -> { 'x': [x labels], 'y': [y vals] }
  """
  # figsize = [5, 7]
  if type(data) is dict:
    data = list(data.items())
  else:
    data = zip(*data)

  data = sorted(data, key = lambda x: x[1], reverse = True)

  xval, yval = zip(*data)


  pdf_features = backend_pdf.PdfPages(output_file)

  plt.rcParams['figure.figsize'] = figsize
  fig = plt.figure(dpi = 256)
  ax = plt.subplot(111)

  ax.bar(xval, height = yval, color = 'lightgreen', edgecolor = 'black')

  plt.xticks(xval, rotation = rotation) # {angle in degrees, 'vertical', 'horizontal'}
  # plt.margins(0.2) # margin between bars and axis
  # https://matplotlib.org/api/_as_gen/matplotlib.pyplot.subplots_adjust.html
  # only for figsize [5, 6]
  # plt.subplots_adjust(bottom = 0.125, top = 0.98, right = 0.98, left = 0.1) # NO title, NO ylabel
  # plt.subplots_adjust(bottom = 0.13, top = 0.98, right = 0.98, left = 0.125) # NO title, ylabel
  # plt.subplots_adjust(bottom = 0.125, top = 0.95, right = 0.98, left = 0.125) # with title and ylabel
  # figsize [5, 5]
  plt.subplots_adjust(bottom = 0.145, top = 0.95, right = 0.98, left = 0.125) # with title and ylabel
  # https://stackoverflow.com/a/49449590 # ha = 'right' -> right side of the string is used as anchor
  # ha, va -> horizontal alignment and vertical alignment ? ;)
  plt.setp(ax.xaxis.get_majorticklabels(), rotation = rotation, ha = 'right', rotation_mode = 'anchor')

  if show_values:
    if max(yval) > 150:
      show_values_yoffset = show_values_yoffset + 1
    for x, y in zip(list(range(len(xval))), yval):
      ax.text(x, y + show_values_yoffset, str(y), ha = 'center', rotation = 'horizontal')

  if title is not None:
    ax.set_title(title)
  if xlabel is not None:
    ax.set_xlabel(xlabel)
  if ylabel is not None:
    ax.set_ylabel(ylabel)

  pdf_features.savefig(fig)
  plt.close(fig)
  pdf_features.close()

################################################################################

def xgb_feature_plot(model_file, output_file):
  with open(model_file, mode = 'rb') as infile:
    clf = pickle.load(infile)

  if not clf:
    print('Error unpickling model from [{0}]'.format(model_file))
    sys.exit(-1)

  pdf_features = backend_pdf.PdfPages(out_file)

  plt.rcParams['figure.figsize'] = [12, 7] # 15, 10
  fig = plt.figure(dpi = 256)
  axes = plt.subplot(111)
  xgb.plot_importance(clf, ax = axes, height = 0.5, color = 'lightgreen',  edgecolor = 'black', title = 'Feature Importance', xlabel = 'F-score', ylabel = 'Features', importance_type = 'weight', grid = False, show_values = True)
  pdf_features.savefig(fig)
  plt.close(fig)
  pdf_features.close()


if __name__ == '__main__':

  try:
    model_file = sys.argv[1]
    out_file = sys.argv[2]
  except:
    print('Usage: {0} <model_to_print_features_from> <pdf_file_to_write_to>'.format(sys.argv[0]))
    sys.exit(-1)

  xgb_feature_plot(model_file, out_file)

  print('Finished')

  sys.exit(0)
