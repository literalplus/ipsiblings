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
        # apply for IPv6 as well: https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
        # TODO: Why are we doing this? Is this necessary? We use raw sockets anyways?
        '/proc/sys/net/ipv4/tcp_keepalive_time': 10,  # start TCP keepalive after 10 seconds
        '/proc/sys/net/ipv4/tcp_keepalive_intvl': 10,  # send TCP keepalive packet every 10 seconds
        # ref: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/net.html - all bytes
        '/proc/sys/net/core/wmem_max': 212992000,  # 212 MB; maximum send socket buffer (window)
        '/proc/sys/net/core/wmem_default': 212992000,  # default send socket buffer (window)
        '/proc/sys/net/core/rmem_max': 212992000,  # maximal receive socket buffer (window)
        '/proc/sys/net/core/rmem_default': 212992000,  # default receive socket buffer (window)
        # ref: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#pid-max
        # apparently, pid_max can be safely reduced later:
        # https://serverfault.com/questions/648287/reduce-pid-max-safely
        # allow a huge number of processes/threads/PIDs (default 32k if < 32 CPU threads)
        '/proc/sys/kernel/pid_max': 327680,
        '/proc/sys/kernel/threads-max': 1283200,  # allow a huge number of processes/threads/PIDs
        # ref: https://www.kernel.org/doc/html/latest/admin-guide/sysctl/vm.html
        # TODO: Isn't the ratio ignored if we set overcommit_memory to 1 (not 2)? Why set this?
        '/proc/sys/vm/overcommit_ratio': 5000,  # python parallelism requires lots of vm -> overcommit
        '/proc/sys/vm/overcommit_memory': 1  # 1 = assume there is always enough memory
    }

    def __init__(self):
        self.original_values: Dict[str, str] = {}

    def apply(self):
        self.original_values = self._read_current_sysctls()
        self._store_to_file(self.original_values)
        for sysctl, new_value in self._RECOMMENDED_SYSCTLS:
            self._set_sysctl(sysctl, new_value)

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
        for sysctl, original_value in self.original_values:
            try:
                self._set_sysctl(sysctl, original_value)
            except Exception:
                log.exception(f'Failed to reset {sysctl} to original value {original_value}')


class FirewallTuner(OsTuner):
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
