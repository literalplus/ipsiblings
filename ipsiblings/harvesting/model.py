import abc
import multiprocessing
import threading
from typing import Optional

from ipsiblings import liblog

log = liblog.get_root_logger()


class HarvestProvider(metaclass=abc.ABCMeta):
    def __init__(self, interval: int, requested_run_count: int):
        self.interval = interval

        self.dispatch_thread: Optional[threading.Thread] = None
        self.run_thread: Optional[threading.Thread] = None
        self.requested_run_count = requested_run_count

        self.mp_manager = multiprocessing.Manager()
        self.stop_event = self.mp_manager.Event()
        self._run_counter = self.mp_manager.Value('I', 1)
        self._runs_finished = self.mp_manager.Event()

    def start_async(self):
        """Start a Thread running the _start method to do harvesting"""
        self.dispatch_thread = threading.Thread(
            target=self._dispatch_all_runs, name=type(self).__name__ + ' Dispatch',
        )
        self.dispatch_thread.start()

    def _dispatch_all_runs(self):
        """Dispatches a new harvester run every time the interval has passed"""
        # ASSUMPTION: This method is the only one *writing* to self.run_counter
        while True:
            run_number = self._run_counter.value
            log.info(f'{type(self).__name__} - Run {run_number}')
            self.run_thread = threading.Thread(
                target=self._do_single_run,
                name=f'{type(self).__name__} Run  {run_number}',
                args=(run_number,),
            )
            self.run_thread.start()
            if run_number >= self.requested_run_count:
                self.run_thread.join(timeout=1)  # second
                self._handle_runs_finished()
                self._runs_finished.set()
                break
            # Note that this is *NOT* thread-safe, but we are the only writing thread anyways.
            # Python sadly does not seem to have an equivalent to AtomicLong.
            self._run_counter.set(self._run_counter.value + 1)
            # Wait until the interval has passed or the stop event is set
            try:
                if self.stop_event.wait(timeout=self.interval):
                    break
            except KeyboardInterrupt:
                log.info('Aborted dispatching runs due to KeyboardInterrupt')
                return

    @abc.abstractmethod
    def _do_single_run(self, run_number: int):
        """Called from _start every time a harvest run is due according to the interval"""
        raise NotImplementedError

    @abc.abstractmethod
    def _handle_runs_finished(self):
        """Clean up after last run"""
        raise NotImplementedError

    @abc.abstractmethod
    def process_queued_results(self):
        """
        Process some queued results, however does not block longer than the interval.
        This is due to the fact that all processors are called from the main thread,
        and we do not want to starve other providers.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def terminate_processing(self):
        raise NotImplementedError

    def is_finished(self):
        return self._runs_finished.is_set()
