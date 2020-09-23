# libsiblings/plot.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#

from typing import List

import matplotlib
import matplotlib.backends.backend_pdf
from matplotlib import pyplot

from ipsiblings import liblog
from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling
from ipsiblings.evaluation.property.outliers_mean import MeanOutlierRemovalProperty
from ipsiblings.evaluation.property.spline import SplineProperty

log = liblog.get_root_logger()


def _configure_plot_appearance(axis1, evaluated_sibling):
    pyplot.legend(loc='lower right')
    first_domain = sorted(list(evaluated_sibling.domains))[0] if evaluated_sibling.domains else 'no domain'
    titlestr = f'{first_domain}\n' \
               f'{evaluated_sibling.series[4].target_ip} / {evaluated_sibling.series[6].target_ip}'
    pyplot.title(titlestr, fontsize=10)
    pyplot.xlabel('reception time (h)')
    pyplot.ylabel('offset (ms)')
    ticks = axis1.get_xticks() / 3600  # set xticks on an hourly basis
    ticks = [round(t, 1) for t in ticks]
    axis1.set_xticklabels(ticks)


def _plot_axes(evaluated_sibling, fig):
    cleaned_prop = evaluated_sibling.get_property(MeanOutlierRemovalProperty)
    axes = fig.add_subplot(nrows=1, ncols=1, index=1)  # full page
    # 'bo' -> blue circles -> fmt parameter https://matplotlib.org/api/_as_gen/matplotlib.pyplot.plot.html
    axes.plot(cleaned_prop[4].KEY_RECEPTION_TIME, cleaned_prop[4].offsets, 'bo', color='blue', alpha=0.4, label='IPv4')
    axes.plot(cleaned_prop[6].KEY_RECEPTION_TIME, cleaned_prop[6].offsets, 'bo', color='red', alpha=0.4, label='IPv6')
    if evaluated_sibling.has_property(SplineProperty):
        spline_prop = evaluated_sibling.get_property(SplineProperty)
        axes.plot(spline_prop[4].reception_times, spline_prop[4].offsets, linewidth=4, color='blue', alpha=0.4)
        axes.plot(spline_prop[6].reception_times, spline_prop[6].offsets, linewidth=4, color='red', alpha=0.4)
    return axes


def _plot_evaluated(
        evaluated_sibling: EvaluatedSibling, plot_function, **plotkwargs
) -> bool:
    """
    Plot data to a matplotlib.pyplot figure.
    """
    if not evaluated_sibling.has_property(MeanOutlierRemovalProperty):
        log.warning(f'Unable to plot {evaluated_sibling}, outlier removal failed/missing.')
        return False
    fig = pyplot.figure()
    axes = _plot_axes(evaluated_sibling, fig)
    _configure_plot_appearance(axes, evaluated_sibling)
    plot_function(fig, **plotkwargs)
    pyplot.close(fig)
    return True


def plot_all(evaluated_siblings: List[EvaluatedSibling], out_path):
    """
    Plots all given siblings.
    """
    with matplotlib.rc_context(rc={'interactive': False}):
        pdf_pages = matplotlib.backends.backend_pdf.PdfPages(out_path)

        def plotfunc(fig, pdf):
            pdf.savefig(fig)

        drawn_plots = 0
        for evaluated_sibling in evaluated_siblings:
            if _plot_evaluated(evaluated_sibling, plotfunc, pdf=pdf_pages):
                drawn_plots = drawn_plots + 1

        if pdf_pages:
            pdf_pages.close()

    log.info(f'Plotted [{drawn_plots}] candidates to file [{out_path}]')
