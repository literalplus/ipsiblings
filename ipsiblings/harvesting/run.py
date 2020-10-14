from typing import List

from ipsiblings.harvesting.tcpts.tcptsharvester import TcpTsHarvester
from .model import HarvestProvider
from .. import liblog
from ..config import HarvesterConfig, AppConfig
from ..model import PreparedTargets, NicInfo, const

log = liblog.get_root_logger()


def run(prepared_targets: PreparedTargets, conf: AppConfig, nic: NicInfo) -> bool:
    if conf.flags.do_harvest:
        if prepared_targets.has_timestamps() and not conf.flags.always_harvest:
            log.warning(f'Not harvesting, it was already done - {prepared_targets.kind}')
            return False
        log.info('Starting harvesting dispatcher ...')
        try:
            providers = _make_providers(conf.harvester, nic, prepared_targets)
            _dispatch_harvesting(providers)
        finally:
            prepared_targets.notify_timestamps_added()
        return True
    else:
        log.info(f'No harvesting requested.')
        return False


def _make_providers(conf: HarvesterConfig, nic: NicInfo, prepared_targets: PreparedTargets):
    providers: List[HarvestProvider] = []
    if const.HarvesterChoice.TCP_TS in conf.harvesters:
        providers.append(TcpTsHarvester(nic, conf, prepared_targets))
    return providers


def _dispatch_harvesting(providers: List[HarvestProvider]):
    for provider in providers:
        log.info(f'Starting harvest provider {type(provider).__name__}...')
        provider.start_async()
    log.info(f'Started all harvest providers.')
    any_still_running = True
    while any_still_running:
        any_still_running = False
        for provider in providers:
            if provider.is_finished():
                continue
            any_still_running = True
            provider.process_queued_results()
    log.info('All harvest providers have finished.')
    for provider in providers:
        provider.terminate_processing()
        log.info(f'Terminated harvest provider {type(provider).__name__}.')
