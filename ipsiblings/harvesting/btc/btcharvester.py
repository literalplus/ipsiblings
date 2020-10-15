import multiprocessing
import queue
from typing import Optional

from ipsiblings import liblog
from ipsiblings.config import HarvesterConfig
from ipsiblings.harvesting.btc._connectionhandler import ConnectionHandler
from ipsiblings.harvesting.model import HarvestProvider
from ipsiblings.model import PreparedTargets

log = liblog.get_root_logger()


class BtcHarvester(HarvestProvider):
    def __init__(self, conf: HarvesterConfig, prepared_targets: PreparedTargets):
        number_runs = int(conf.runtime / conf.btc_interval)
        super(BtcHarvester, self).__init__(conf.btc_interval, number_runs)
        self.target_tuples = [(t.address, t.port) for t in prepared_targets]
        self.connection_handler = ConnectionHandler(self.mp_manager, self.stop_event, self._runs_finished)
        self.handler_proc: Optional[multiprocessing.Process] = None
        self.final_timeout = conf.final_timeout

    def start_async(self):
        self.handler_proc = multiprocessing.Process(
            target=self.connection_handler.run(),
            name='BTC Connection Handler',
        )
        self.handler_proc.start()
        super(BtcHarvester, self).start_async()

    def _do_single_run(self, run_number: int):
        for ip_and_port in self.target_tuples:
            self.connection_handler.connect_q.put(ip_and_port)

    def _handle_runs_finished(self):
        self.connection_handler.all_connections_created.wait(30)  # seconds

    def process_queued_results(self):
        while True:
            try:
                record = self.connection_handler.result_q.get(timeout=5)
                self._process_record(record)
            except queue.Empty:
                break
            except Exception:
                log.exception('Unexpected error processing BTC records')
                break

    def _process_record(self, record):
        # FIXME
        log.debug(f'BTC record: {record}')

    def terminate_processing(self):
        if not self.connection_handler.all_connections_closed.wait(timeout=self.final_timeout):
            log.warning('Not all BTC connections closed naturally after final timeout!')
        self.stop_event.set()
        self.process_queued_results()
