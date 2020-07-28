# libsiblings/plot.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#

import os

import matplotlib  # rc_context -> {'interactive': False }
import matplotlib.backends.backend_pdf  # PdfPages

from .. import libconstants as const
from .. import liblog

log = liblog.get_root_logger()


def plot_all(candidates, fname, func=None, funckwargs=None):
    """
    Plots all given SiblingCandidate objects.
    """
    if funckwargs is None:
        funckwargs = {}

    with matplotlib.rc_context(rc={'interactive': False}):
        plotfile = os.path.abspath(os.path.join(const.BASE_DIRECTORY, fname))

        if func:
            pp = None
            plotfunc = func
            args = funckwargs
        else:
            pp = matplotlib.backends.backend_pdf.PdfPages(plotfile)

            def pfunc(fig, pdf=None):
                if pdf:
                    pdf.savefig(fig)

            plotfunc = pfunc
            args = {'pdf': pp}

        counter = 0
        for s in candidates:
            if s.plot(func=plotfunc, funckwargs=args):
                counter = counter + 1

        if pp:
            pp.close()

    log.info('Plotted [{0}] candidates to file [{1}]'.format(counter, plotfile))
