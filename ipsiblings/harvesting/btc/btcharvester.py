import multiprocessing
import queue
from typing import List

from ipsiblings import logsetup
from ipsiblings.config import AppConfig
from ipsiblings.harvesting.btc._connectionhandler import ConnectionHandler
from ipsiblings.harvesting.btc.export import BtcExporter
from ipsiblings.harvesting.model import HarvestProvider
from ipsiblings.model import PreparedTargets

log = logsetup.get_root_logger()


class BtcHarvester(HarvestProvider):
    def __init__(self, conf: AppConfig, prepared_targets: PreparedTargets):
        number_runs = int(conf.harvester.runtime / conf.harvester.btc_interval)
        super(BtcHarvester, self).__init__(conf.harvester.btc_interval, number_runs)
        self.target_tuples = [(t.ip_version, t.address, t.port) for t in prepared_targets]
        self.connect_q = self.mp_manager.Queue()
        self.result_q = self.mp_manager.Queue()
        self.connection_handlers: List[ConnectionHandler] = []
        for _ in range(0, 2):
            self.connection_handlers.append(
                ConnectionHandler(self.mp_manager, self.stop_event, self._runs_finished, self.connect_q, self.result_q)
            )
        self.final_timeout = conf.harvester.final_timeout
        self.exporter = BtcExporter(conf.base_dir)
        self.exporter.cache_file = True

    def start_async(self):
        for i, handler in enumerate(self.connection_handlers):
            handler_proc = multiprocessing.Process(
                target=handler.run,
                name=f'BTC Connection Handler {i}',
            )
            handler_proc.start()
        super(BtcHarvester, self).start_async()

    def _do_single_run(self, run_number: int):
        log.debug(f'Starting BTC measurement {run_number} of {len(self.target_tuples)} nodes.')
        for version_ip_and_port in self.target_tuples:
            self.connect_q.put(version_ip_and_port)

    def _handle_runs_finished(self):
        for handler in self.connection_handlers:
            handler.all_connections_created.wait(30)  # seconds

    def process_queued_results(self):
        for _ in range(0, 5_000):
            try:
                record = self.result_q.get(timeout=2)
                self._process_record(record)
            except queue.Empty:
                return
            except Exception:
                log.exception('Unexpected error processing BTC records')
                return

    def _process_record(self, record):
        self.exporter.export_record(record)

    def terminate_processing(self):
        for i, handler in enumerate(self.connection_handlers):
            # Wait the full timeout for the first handler, for later handlers the timeout is already exceeded
            # and we do not need to wait
            timeout = self.final_timeout if i == 0 else 0
            if not handler.all_connections_closed.wait(timeout=timeout):
                log.warning(f'Not all BTC connections closed naturally after final timeout! - {i}')
        self.stop_event.set()
        self.process_queued_results()
        self.exporter.close()
