# keyscan.py
#
# (c) 2019 Marco Starke
#
# keyscan is scriptable and very efficient to query multiple nodes concurrently as stated in the man page
# tail -n +2 candidatepairs.csv | awk -F ";" '{print $1","$3","$5}' | head -1 | ssh-keyscan -f -
#


import pathlib
import shlex
import subprocess
import threading
from typing import Dict, Tuple

from . import libconstants as const
from . import liblog
from .model import SiblingCandidate

log = liblog.get_root_logger()


def assign_key_data(candidates: Dict[str, SiblingCandidate], keyfile, agentfile):
    # load keys
    keys = {4: {}, 6: {}}
    k = keys[4]
    with open(keyfile, mode='r') as infile:
        for l in infile:
            line = l.strip()
            if not line:
                continue
            if line.startswith('='):
                k = keys[6]
                continue

            ip, type, key = line.split()
            if ip not in k:
                k[ip] = {type: key}
            else:
                k[ip][type] = key

    # load agents
    agents = {4: {}, 6: {}}
    a = agents[4]
    with open(agentfile, mode='r') as infile:
        for l in infile:
            line = l.strip()
            if not line:
                continue
            if line.startswith('='):
                a = agents[6]
                continue

            ip, agent = line.split(';', 1)
            a[ip] = agent

    # assign keys and agents
    for candidate in candidates.values():
        ip4, ip6 = candidate.ip4, candidate.ip6
        if ip4 in keys[4] and ip6 in keys[6]:
            candidate.addsshkeys(keys[4][ip4], const.IP4)
            candidate.addsshkeys(keys[6][ip6], const.IP6)
            candidate.ssh_available = True

        if ip4 in agents[4] and ip6 in agents[6]:
            candidate.addsshagent(agents[4][ip4], const.IP4)
            candidate.addsshagent(agents[6][ip6], const.IP6)


class Keyscan(object):

    def __init__(
            self, candidates: Dict[Tuple, SiblingCandidate], directory=None, timeout=600,
            key_file_name=const.SSH_KEYS_FILENAME, agent_file_name=const.SSH_AGENTS_FILENAME,
            keyscan_command=const.SSH_KEYSCAN_COMMAND
    ):
        # candidates: type(candidate) == SiblingCandidate
        self.directory = directory
        self.timeout = timeout
        self.keyfile = key_file_name  # 'ssh-keys.txt'
        self.agentfile = agent_file_name  # 'ssh-agents.txt'
        self.keyscan_command = keyscan_command  # 'ssh-keyscan -f -'
        self.v4map = {}
        self.v6map = {}

        for c in candidates.values():
            if c.has_ssh() and c.keys_match() != None:  # ssh available? keys already loaded? (None if no keys available)
                continue

            ip4, ip6 = c.ip4, c.ip6
            if ip4 in self.v4map:
                self.v4map[ip4].add(c)
            else:
                self.v4map[ip4] = set([c])
            if ip6 in self.v6map:
                self.v6map[ip6].add(c)
            else:
                self.v6map[ip6] = set([c])

    def _load_ssh_keys(self):
        filename = pathlib.Path(self.directory, self.keyfile)
        if not filename.is_file():
            return None

        keys = {4: {}, 6: {}}
        k = keys[4]
        with open(filename, mode='r') as infile:
            for l in infile:
                line = l.strip()
                if not line:
                    continue
                if line.startswith('='):
                    k = keys[6]
                    continue

                ip, type, key = line.split()
                if ip not in k:
                    k[ip] = {type: key}
                else:
                    k[ip][type] = key

        return keys

    def _load_ssh_agents(self):
        filename = pathlib.Path(self.directory, self.agentfile)
        if not filename.is_file():
            return None

        agents = {4: {}, 6: {}}
        a = agents[4]
        with open(filename, mode='r') as infile:
            for l in infile:
                line = l.strip()
                if not line:
                    continue
                if line.startswith('='):
                    a = agents[6]
                    continue

                ip, agent = line.split(';', 1)
                a[ip] = agent

        return agents

    def _scan(self, in_data, out_data, err_data):
        proc = subprocess.Popen(shlex.split(self.keyscan_command), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True, cwd=self.directory)
        out, err = proc.communicate(input=in_data, timeout=self.timeout)
        out_data.append(out)
        err_data.append(err)

    def _map_keys(self, keys, version=None):
        if version == const.IP4:
            ipmap = self.v4map
        elif version == const.IP6:
            ipmap = self.v6map
        else:
            return False

        for line in keys:
            ip, type, key = line.split()
            for cand in ipmap[ip]:
                cand.addsshkey(type, key, version)

    def _map_agents(self, agents, version=None):
        if version == const.IP4:
            ipmap = self.v4map
        elif version == const.IP6:
            ipmap = self.v6map
        else:
            return False

        for ip, agent in agents.items():
            for cand in ipmap[ip]:
                cand.addsshagent(agent, version=version)

    def has_keys(self):
        ssh_keys = self._load_ssh_keys()
        if not ssh_keys:
            return False
        # { ip: { type: key } }
        ip4keys, ip6keys = ssh_keys[4], ssh_keys[6]
        for ip, keys in ip4keys.items():
            if ip in self.v4map:
                for c in self.v4map[ip]:
                    c.addsshkeys(keys, const.IP4)
            else:
                log.warning('{0} not found in candidates!'.format(ip))
        for ip, keys in ip6keys.items():
            if ip in self.v6map:
                for c in self.v6map[ip]:
                    c.addsshkeys(keys, const.IP6)
            else:
                log.warning('{0} not found in candidates!'.format(ip))

        ssh_agents = self._load_ssh_agents()
        if ssh_agents:
            agents4, agents6 = ssh_agents[4], ssh_agents[6]
            for ip, agent in agents4.items():
                if ip in self.v4map:
                    for c in self.v4map[ip]:
                        c.addsshagent(agent, const.IP4)
                else:
                    log.warning('{0} [{1}] not found in candidates!'.format(ip, agent))
            for ip, agent in agents6.items():
                if ip in self.v6map:
                    for c in self.v6map[ip]:
                        c.addsshagent(agent, const.IP6)
                else:
                    log.warning('{0} [{1}] not found in candidates!'.format(ip, agent))
        else:
            log.info('No SSH agents available')

        return True

    def run(self, write_keyfile=True, split_output=False):
        if not self.v4map or not self.v6map:
            return False

        ip4in = '\n'.join(list(self.v4map.keys()))
        ip6in = '\n'.join(list(self.v6map.keys()))
        ip4out = []
        ip6out = []
        ip4err = []
        ip6err = []

        t4 = threading.Thread(target=self._scan, args=(ip4in, ip4out, ip4err))
        t6 = threading.Thread(target=self._scan, args=(ip6in, ip6out, ip6err))
        t4.start()
        t6.start()
        t4.join()
        t6.join()

        filtered4 = [line.strip('#').strip() for line in ip4err[0].strip().split('\n') if line.startswith('#')]
        filtered6 = [line.strip('#').strip() for line in ip6err[0].strip().split('\n') if line.startswith('#')]
        v4agents = {ip[:-3]: agent for ip, agent in [f.split(' ', 1) for f in filtered4]}  # remove :22 from ip
        v6agents = {ip[:-3]: agent for ip, agent in [f.split(' ', 1) for f in filtered6]}

        if write_keyfile:
            self.write_keys(str(ip4out[0]), str(ip6out[0]), split=split_output)
            self.write_agents(v4agents, v6agents, split=split_output)

        keys4 = ip4out[0].strip().split('\n')
        keys6 = ip6out[0].strip().split('\n')
        # map keys to SiblingCandidate objects
        self._map_keys(keys4, version=const.IP4)
        self._map_keys(keys6, version=const.IP6)
        self._map_agents(v4agents, version=const.IP4)
        self._map_agents(v6agents, version=const.IP6)

        return True

    def write_keys(self, ssh_keyscan_ip4out, ssh_keyscan_ip6out, split=False):
        if split:
            v4filename = '.'.join([self.keyfile.split('.')[0], 'v4', self.keyfile.split('.')[1]])  # insert 'v4'
            v6filename = '.'.join([self.keyfile.split('.')[0], 'v6', self.keyfile.split('.')[1]])  # insert 'v6'
            v4file = pathlib.Path(self.directory, v4filename)
            v6file = pathlib.Path(self.directory, v6filename)

            with open(v4file, mode='w') as v4out, open(v6file, mode='w') as v6out:
                v4out.write(ssh_keyscan_ip4out)
                v6out.write(ssh_keyscan_ip6out)
        else:
            filename = pathlib.Path(self.directory, self.keyfile)
            with open(filename, mode='w') as outfile:
                outfile.write(ssh_keyscan_ip4out)
                outfile.write('\n=\n\n')  # empty line, =, empty line
                outfile.write(ssh_keyscan_ip6out)

    def write_agents(self, ssh_agents_ip4err, ssh_agents_ip6err, split=False):
        if split:
            v4filename = '.'.join([self.agentfile.split('.')[0], 'v4', self.agentfile.split('.')[1]])  # insert 'v4'
            v6filename = '.'.join([self.agentfile.split('.')[0], 'v6', self.agentfile.split('.')[1]])  # insert 'v6'
            v4file = pathlib.Path(self.directory, v4filename)
            v6file = pathlib.Path(self.directory, v6filename)

            with open(v4file, mode='w') as v4out, open(v6file, mode='w') as v6out:
                for ip, agent in ssh_agents_ip4err.items():
                    v4out.write(ip + ';' + agent + '\n')
                for ip, agent in ssh_agents_ip6err.items():
                    v6out.write(ip + ';' + agent + '\n')
        else:
            filename = pathlib.Path(self.directory, self.agentfile)
            with open(filename, mode='w') as outfile:
                for ip, agent in ssh_agents_ip4err.items():
                    outfile.write(ip + ';' + agent + '\n')
                outfile.write('\n=\n\n')  # empty line, =, empty line
                for ip, agent in ssh_agents_ip6err.items():
                    outfile.write(ip + ';' + agent + '\n')
