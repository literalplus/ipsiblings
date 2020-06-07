# settings.py
#
# (c) 2018 Marco Starke
#
# Linux settings taken from Scheitle et al.
# https://github.com/tumi8/siblings/blob/master/src/measure_ts.py#L149
#
# Use a portable uname interface
# https://docs.python.org/3/library/platform.html
#

"""
Holds platform dependent OS configuration
"""

import os
import sys
import shlex
import inspect
import platform
import subprocess
import scapy.all as scapy
from scipy import interpolate

from . import libconstants as const
from . import liblog
log = liblog.get_root_logger()


def dependency_error():
  """
  Need Python >= (libconstants.PYTHON_VERSION_MAJOR, libconstants.PYTHON_VERSION_MINOR)
  Scapy:
  Necessary unless PR is not merged or TypeError gets fixed for Python 3.
  https://github.com/secdev/scapy/pull/1388
  Finally, got merged on 11 Jun 2018
  https://github.com/secdev/scapy/commit/a1ccd30784e997acc42dd67fa94a7ea22574934d
  Scipy:
  https://github.com/scipy/scipy/issues/8535
  In need of lifted increasing x values check -> '>=' instead of '>' for LSQUnivariateSpline
  Still not merged (14 Nov 2018)
  File: scipy/interpolate/fitpack2.py line ~730
  """

  v4source = inspect.getsource(scapy.TracerouteResult.get_trace).splitlines()
  v6source = inspect.getsource(scapy.TracerouteResult6.get_trace).splitlines()

  # should iterate with 'iteritems' and check boolean value at 'y[0]'
  scapy_error = any((l.strip().startswith('m = min') and 'itervalues' in l) for l in v4source)
  scapy_error = scapy_error or any((l.strip().startswith('m = min') and 'itervalues' in l) for l in v6source)

  # if not all(diff(x) > 0.0) should only check for '>=' NOT only '>'
  scipysrc = inspect.getsource(interpolate.LSQUnivariateSpline.__init__).splitlines()
  scipy_error = any((l.strip().startswith('if not all(diff(x)') and '>=' not in l) for l in scipysrc)

  python_version_error = sys.version_info < (const.PYTHON_VERSION_MAJOR, const.PYTHON_VERSION_MINOR)

  if scapy_error:
    log.error("Scapy's 'get_trace' function not patched!")

  if scipy_error:
    log.error("Scipy's interpolate.LSQUnivariateSpline initialization must allow increasing values (NOT strictly)!")

  if python_version_error:
    log.error("Please update your Python 3 installation to version {0}.{1}!".format(const.PYTHON_VERSION_MAJOR, const.PYTHON_VERSION_MINOR))

  return (scapy_error or scipy_error or python_version_error)

################################################################################

class Settings(object):

  def __init__(self, backup_to_file = True):
    """
    Determines the underlying operating system and optimizes network settings.
    If backup_to_file is True, a file is written to the pwd 'settings.bak'.
    """
    self.backup = backup_to_file

    self._optimize_system_settings = None
    self._restore_system_settings = None

    self._enable_firewall_rules = None
    self._disable_firewall_rules = None

    self.saved_settings = {}
    self.settings = {}

    self.fwrules = {}

    # uname_result(system, node, release, version, machine, processor)
    # access with e.g. self.uname.system
    self.uname = platform.uname()

    if self.uname.system.lower().startswith('freebsd'):
      raise NotImplementedError()

    elif self.uname.system.lower().startswith('darwin'):
      raise NotImplementedError()

    elif self.uname.system.lower().startswith('linux'):

      self.settings = self._linux_settings()
      activate_rules, deactivate_rules = self._linux_firewall_rules()
      self.fwrules['activate'] = activate_rules
      self.fwrules['deactivate'] = deactivate_rules

      # optimize os settings
      self._optimize_system_settings = self._linux_optimize
      self._restore_system_settings = self._linux_restore
      # apply firewall rules
      self._enable_firewall_rules = self._linux_firewall_enable
      self._disable_firewall_rules = self._linux_firewall_disable
      # optimize time sync settings
      if const.TIME_SYNC_STOP_COMMAND:
        self._time_sync_stop_command = const.TIME_SYNC_STOP_COMMAND
      else:
        self._time_sync_stop_command = 'timedatectl set-ntp off'
      if const.TIME_SYNC_START_COMMAND:
        self._time_sync_start_command = const.TIME_SYNC_START_COMMAND
      else:
        self._time_sync_start_command = 'timedatectl set-ntp on'

    elif self.uname.system.lower().startswith('solaris'):
      raise NotImplementedError()

    elif self.uname.system.lower().startswith('win'):
      raise NotImplementedError()

    else:
      raise ValueError('Unknown operating system: {0}'.format(self.uname.system))


  def _backup_to_file(self):
    """
    Backs up the saved_settings dict to 'settings.bak' in the current working directory.
    This function is not intended for explicit usage.
    If backup_to_file is set at object creation, the function is called during
    enabling the OS specific optimization options.
    """
    if self.saved_settings:
      current_option, current_value = None, None
      try:
        filename = os.path.join(os.getcwd(), const.OS_SETTINGS_FILE_NAME)
        with open(filename, mode = "w") as outfile:
          for option, value in self.saved_settings.items():
            current_option, current_value = option, value
            outfile.write(option)
            outfile.write(' = ')
            outfile.write(value)
            outfile.write('\n')
        return True
      except Exception as e:
        log.error('Exception while backing up [{0}] and value [{1}]: {2}'.format(current_option, current_value, str(e)))
        return False
    else:
      log.warning('Nothing to write, empty saved_settings dict!')
      return False


  def get_system_info(self):
    """
    Returns a dict of available system information collected at object creation time.
    """
    return self.uname._asdict()

  def optimize_system_config(self):
    """True on success, False otherwise"""
    if self._optimize_system_settings:
      return self._optimize_system_settings()
    return False

  def restore_system_config(self):
    """True on success, False otherwise"""
    if self._restore_system_settings:
      return self._restore_system_settings()
    return False

  def enable_timesync(self):
    """Returns command exit value"""
    ret = subprocess.run(shlex.split(self._time_sync_start_command))
    return ret.returncode

  def disable_timesync(self):
    """Returns command exit value"""
    ret = subprocess.run(shlex.split(self._time_sync_stop_command))
    return ret.returncode

  def enable_firewall_rules(self):
    """True on success, False otherwise"""
    if self._enable_firewall_rules:
      return self._enable_firewall_rules()
    return False

  def disable_firewall_rules(self):
    """True on success, False otherwise"""
    if self._disable_firewall_rules:
      return self._disable_firewall_rules()
    return False

################################
######## LINUX

  def _linux_firewall_rules(self):
    rules_activate = []
    rules_deactivate = []

    rules_activate.append('iptables -t raw -A PREROUTING -p tcp --dport {0} -j DROP'.format(const.V4_PORT))
    rules_activate.append('ip6tables -t raw -A PREROUTING -p tcp --dport {0} -j DROP'.format(const.V6_PORT))

    rules_deactivate.append('iptables -t raw -D PREROUTING -p tcp --dport {0} -j DROP'.format(const.V4_PORT))
    rules_deactivate.append('ip6tables -t raw -D PREROUTING -p tcp --dport {0} -j DROP'.format(const.V6_PORT))

    return (rules_activate, rules_deactivate)

  def _linux_settings(self):
    settings = {}
    # apply for IPv6 as well: https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt
    settings['/proc/sys/net/ipv4/tcp_keepalive_time'] = 10 # start TCP keepalive after 10 seconds
    settings['/proc/sys/net/ipv4/tcp_keepalive_intvl'] = 10 # send TCP keepalive packet every 10 seconds
    settings['/proc/sys/net/core/wmem_max'] = 212992000 # maximal send socket buffer (window)
    settings['/proc/sys/net/core/wmem_default'] = 212992000 # default send socket buffer (window)
    settings['/proc/sys/net/core/rmem_max'] = 212992000 # maximal receive socket buffer (window)
    settings['/proc/sys/net/core/rmem_default'] = 212992000 # default receive socket buffer (window)
    settings['/proc/sys/kernel/pid_max'] = 327680 # allow a huge number of processes/threads/PIDs
    settings['/proc/sys/kernel/threads-max'] = 1283200 # allow a huge number of processes/threads/PIDs
    settings['/proc/sys/vm/overcommit_ratio'] = 5000 # 5000 # python parallelism requires lots of vm -> overcommit
    settings['/proc/sys/vm/overcommit_memory'] = 1 # make sure vm overcommitting is active
    return settings

  def _linux_optimize(self):
    # first at all read ALL current values and keep them for later restore
    current_option = None
    try:
      for option in self.settings.keys():
        current_option = option
        with open(option, mode = "r") as opt:
          self.saved_settings[option] = opt.read().strip() # remove any whitespace
    except Exception as e:
      log.error('Exception while saving default option [{0}]: {1}'.format(current_option, str(e)))
      return False # immediately return and do not modify anything without 'backup'

    if self.backup: # backup to file if requested
      if not self._backup_to_file():
        return False # do not continue with writing new options if backup failed

    # set new values during execution
    current_option = None # reset to None
    error = False
    try:
      for option in self.settings.keys():
        current_option = option
        with open(option, mode = "w") as opt:
          opt.write(str(self.settings[option]))
    except Exception as e:
      log.warning('Exception while writing new option [{0}]'.format(current_option))
      error = True

    return error

  def _linux_restore(self):
    error = False
    opt_str = None
    val_str = None
    try:
      for option, saved_value in self.saved_settings.items():
        opt_str = option
        val_str = saved_value
        with open(option, mode = "w") as opt:
          opt.write(saved_value)
    except Exception as e:
      log.error('Exception while writing value [{0}] to [{1}]: {2}'.format(val_str, opt_str, str(e)))
      error = True

    return error

  def _linux_firewall_enable(self):
    errval = 0
    for rule_cmd in self.fwrules['activate']:
      ret = subprocess.run(shlex.split(rule_cmd))
      if ret.returncode != 0:
        # initial log level is set to warning -> works as expected also before main() execution
        log.warning('Could not execute command "{0}" (returned {1})'.format(rule_cmd, ret.returncode))
      errval = errval + ret.returncode
    return not bool(errval)

  def _linux_firewall_disable(self):
    errval = 0
    for rule_cmd in self.fwrules['deactivate']:
      log.debug('Removing previously enabled rule: [{0}]'.format(rule_cmd))
      ret = subprocess.run(shlex.split(rule_cmd))
      if ret.returncode != 0:
        log.warning('Could not execute command "{0}" (returned {1})'.format(rule_cmd, ret.returncode))
      errval = errval + ret.returncode
    return not bool(errval)

  ################################
