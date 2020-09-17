# settings.py
#
# (c) 2018 Marco Starke


"""
Holds platform dependent OS configuration
"""
import abc
import csv
import os
import platform
import shlex
import subprocess
from typing import Dict, List

from . import libconstants as const
from . import liblog
from .config import OsTunerConfig
from .model import ConfigurationException, DataException, BusinessException

log = liblog.get_root_logger()


class OsTuner(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def apply(self):
        """Tune the configuration, throw an exception on the first issue"""
        raise NotImplementedError

    @abc.abstractmethod
    def try_revert(self):
        """Revert all configuration, only throw an exception if reversion was attempted for all tunings already"""
        raise NotImplementedError


class SysctlTuner(OsTuner):
    # Values taken from https://github.com/tumi8/siblings/blob/master/src/measure_ts.py#L149
    _RECOMMENDED_SYSCTLS = {
        # NOTE: Scheitle et al. set tcp_keepalive_time and tcp_keepalive_intvl, but we do not need this
        # since this applies to the TCP stack, which we circumvent by using raw sockets for TS measurement.
        # ref: https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
        # tcp_keepalive_time: After x seconds (default 2h) of no activity, ask the peer if it is still alive
        # tcp_keepalive_intvl: If no reply to the previous, repeat every x seconds (default 75s) - by default 9 times

        # ref: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/net.html - all bytes, defaults 212 KB
        # we set these to 21.2 MB, in contrast to Scheitle et al. which set them to 212.9 MB (a lot)
        # 212 MB might become an issue for systems that have other TCP traffic as well
        # Minimal Ethernet packet: 64 B (incl. 46 B payload)
        # IPv6 header: 40 B, IPv4 header: 20-60 B
        # TCP header: 20 B + 1.25 B timestamp -> 24 B
        # Eth payloads are 64 and 44 B, resulting in L2 frames of 82 and 64 B
        # Even for 10k nodes, this amounts to (82+64)*10k = 1.46 MB per execution <<< 21.2 MB
        # (and this already ignores that the driver is already sending packets while we are still writing
        # (with python) (which is slow))
        '/proc/sys/net/core/wmem_max': 21299200,  # 21.2 MB; maximum send socket buffer (window)
        '/proc/sys/net/core/wmem_default': 21299200,  # default send socket buffer (window)
        '/proc/sys/net/core/rmem_max': 21299200,  # maximal receive socket buffer (window)
        '/proc/sys/net/core/rmem_default': 21299200,  # default receive socket buffer (window)

        # ref: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/vm.html
        # NOTE: Scheitle et al. also set overcommit_ratio, but this is ignored for
        # overcommit_memory=1, so we skip it.
        '/proc/sys/vm/overcommit_memory': 1,  # 1 = assume there is always enough memory
    }

    def __init__(self):
        self.original_values: Dict[str, str] = {}

    def apply(self):
        self.original_values = self._read_current_sysctls()
        self._store_to_file(self.original_values)
        for sysctl, new_value in self._RECOMMENDED_SYSCTLS.items():
            self._set_sysctl(sysctl, str(new_value))

    def _read_current_sysctls(self) -> Dict[str, str]:
        original_values: Dict[str, str] = {}
        for sysctl in self._RECOMMENDED_SYSCTLS.keys():
            try:
                with open(sysctl, mode="r") as opt:
                    original_values[sysctl] = opt.read().strip()  # remove any whitespace
            except Exception:
                raise BusinessException(f'Failed to read sysctl {sysctl}')
        return original_values

    def _store_to_file(self, original_values: Dict[str, str]):
        """
        Backs up the saved_settings dict to 'settings.bak' in the current working directory.
        This function is not intended for explicit usage.
        If backup_to_file is set at object creation, the function is called during
        enabling the OS specific optimization options.
        """
        if not original_values:
            raise DataException("No settings to back up? Check for earlier errors.")
        filename = os.path.join(os.getcwd(), const.OS_SETTINGS_FILE_NAME)
        with open(filename, mode='w', encoding='utf-8', newline='') as outfile:
            writer = csv.writer(outfile)
            writer.writerows(original_values.items())

    def _set_sysctl(self, sysctl: str, new_value: str):
        try:
            with open(sysctl, mode="w") as opt:
                opt.write(str(new_value))
        except Exception:
            raise BusinessException(f'Failed to set sysctl {sysctl} to {new_value}')

    def try_revert(self):
        for sysctl, original_value in self.original_values.items():
            try:
                self._set_sysctl(sysctl, original_value)
            except Exception:
                log.exception(f'Failed to reset {sysctl} to original value {original_value}')


class FirewallTuner(OsTuner):
    # We drop these packets so that they do not reach the TCP stack, but we see them anyways since we are using
    # raw sockets, which see all bytes on the wire.
    _APPLY_COMMANDS = [
        f'iptables -t raw -A PREROUTING -p tcp --dport {const.V4_PORT} -j DROP',
        f'ip6tables -t raw -A PREROUTING -p tcp --dport {const.V6_PORT} -j DROP'
    ]
    _REVERT_COMMANDS = [
        f'iptables -t raw -D PREROUTING -p tcp --dport {const.V4_PORT} -j DROP',
        f'ip6tables -t raw -D PREROUTING -p tcp --dport {const.V6_PORT} -j DROP'
    ]

    def apply(self):
        for command in self._APPLY_COMMANDS:
            ret = subprocess.run(shlex.split(command))
            if ret.returncode != 0:
                raise BusinessException(
                    f'Failed to add required firewall rule `{command}` - exit code {ret.returncode}'
                )

    def try_revert(self):
        for command in self._REVERT_COMMANDS:
            ret = subprocess.run(shlex.split(command))
            if ret.returncode != 0:
                log.warning(f'Failed to revert firewall rule `{command}` - exit code {ret.returncode}')


class TimesyncTuner(OsTuner):
    # We disable NTP since time adjustments on our side would interfere with TS measurements.
    def apply(self):
        self._set_ntp_state('off')

    def _set_ntp_state(self, state: str):
        ret = subprocess.run(shlex.split(f'timedatectl set-ntp {state}'))
        if ret.returncode != 0:
            raise BusinessException(f'Failed to set-ntp to {state} via timedatectl - exit code {ret.returncode}')

    def try_revert(self):
        self._set_ntp_state('on')


class OsTuning(object):
    def __init__(self, conf: OsTunerConfig):
        """
        Determines the underlying operating system and optimizes network settings.
        A file is written to the pwd 'settings.bak'.
        """
        system_name = platform.uname().system
        if not system_name.lower().startswith('linux'):
            raise ConfigurationException(f'Unsupported operating system: {system_name}')

        self.tuners: List[OsTuner] = []
        if not conf.skip_sysctls:
            self.tuners.append(SysctlTuner())
        if not conf.skip_firewall:
            self.tuners.append(FirewallTuner())
        if not conf.skip_timesync:
            self.tuners.append(TimesyncTuner())

    def apply(self):
        for tuner in self.tuners:
            tuner.apply()

    def try_revert(self):
        for tuner in self.tuners:
            try:
                tuner.try_revert()
            except Exception:
                log.exception(f'Failed to reset OS tuning for {type(tuner).__name__}')
