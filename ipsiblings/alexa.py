# alexa.py
#
# (c) 2018 Marco Starke
#


"""
This module interacts with resolved domain list files (Alexa).
"""

import csv
import io
import os
import random
import socket
import urllib.request
import zipfile

from . import libconstants as const
from . import liblog
from . import libtools
from .libts.candidatepair import CandidatePair

log = liblog.get_root_logger()


class Alexa(object):

    def __init__(self, resolved_file=None):
        """
        This class works with a file containing already resolved Alexa domains.
        The main task is to provide ready to use target/candidate pairs.

        Provide resolved_file for IP lookup. If not provided name resolution must be performed
        using load_toplist_file().
        This will take a very long time even on fast connections to resolve a million entries by using
        the full OS libc stack (getaddrinfo).
        Use resolution from e.g. https://github.com/m-starke/goplayground/blob/master/resolve/resolve.go
        -> https://idea.popcount.org/2013-11-28-how-to-resolve-a-million-domains/
        """
        self.resolved = libtools.SentinelDict()  # { domain: ([ip4], [ip6]) }
        self.resolved_file = resolved_file  # domain; ip4, ip4, ip4; ip6, ip6, ip6, ip6
        self.unresolvable = libtools.SentinelList()  # only if name resolution is performed; holds domains where A and/or AAAA record is not available

        self.toplist = None  # { pos: domain }

        if resolved_file:
            records, nr_records = self._load_resolved(self.resolved_file)
            if records:
                self.resolved.update(records)
                log.info('Loaded {0} already resolved domains from [{1}]'.format(nr_records, self.resolved_file))
                self.resolved.reset_modified()  # reset modified sentinel
            else:
                log.warning('No resolved records file found')

    def _resolve_host_dual(self, hoststr):
        addrv6 = set()
        try:
            # [(family, type, proto, canonname, sockaddr)] -> [sockaddr] -> (address, port, flow info, scope id)
            v6 = socket.getaddrinfo(hoststr, None, socket.AF_INET6)
            for addr in v6:
                addrv6.add(addr[4][0])
        except socket.gaierror:
            return None
        addrv4 = set()
        try:
            # [(family, type, proto, canonname, sockaddr)] -> [sockaddr] -> (address, port)
            v4 = socket.getaddrinfo(hoststr, None, socket.AF_INET)
            for addr in v4:
                addrv4.add(addr[4][0])
        except socket.gaierror:
            return None
        return addrv4, addrv6

    def _load_toplist(self, filename=None, load_remote=False):
        if not filename and load_remote:
            entries = self._load_remote_toplist()  # None on error
            if entries:
                log.info('Loaded Alexa Top Million List from [{0}]'.format(const.ALEXA_URL))
        else:
            entries = {}
            try:
                with open(filename, mode='r', newline='') as alexacsv:
                    reader = csv.reader(alexacsv, delimiter=',')
                    for row in reader:
                        pos, domain = row
                        entries[pos] = domain
            except Exception:  # IOError
                log.warning('Error loading file [{0}]'.format(filename))
                if load_remote:
                    log.info('Try to load Alexa Top List from remote source [{0}] ...'.format(const.ALEXA_URL))
                    entries = self._load_remote_toplist()  # None on error
                else:
                    log.info('Loading remote Alexa Top List not allowed (use -o/--download-alexa)')
                    entries = None

        if not entries:
            log.error('Error loading Alexa Top Million data')

        return entries

    def _load_remote_toplist(self, url=const.ALEXA_URL, remote_fname=const.ALEXA_FILE_NAME):
        """
        Load the current Alexa Top Million file from ALEXA_URL into memory.
        To save the new list use 'save_toplist(fname)'.
        """
        toplist = {}
        try:
            httpresponse = urllib.request.urlopen(url)
            with zipfile.ZipFile(io.BytesIO(httpresponse.read())) as zf:
                with zf.open(remote_fname) as csvfile:
                    for line in csvfile.readlines():
                        pos, domain = line.decode('utf-8').strip().split(',')
                        toplist[pos] = domain
        except Exception as e:
            log.warning('Exception: {0} - {1}'.format(type(e).__name__, e))
            toplist = None

        return toplist

    def load_toplist_file(self, fname, remote=True):  # only necessary if resolution should be performed
        entries = self._load_toplist(filename=fname, load_remote=remote)
        if entries:
            self.toplist = entries
            return True
        else:
            self.toplist = None
            return False

    def save_toplist(self, fname):
        with open(fname, mode='w', newline='') as alexafile:
            writer = csv.writer(alexafile, delimiter=',')
            for pos, domain in self.toplist.items():
                writer.writerow([pos, domain])

    def _load_resolved(self, fname, delimiter=';', ip_delimiter=','):
        records = {}
        counter = 0
        try:
            with open(fname, mode='r', newline='') as alexacsv:
                reader = csv.reader(alexacsv, delimiter=delimiter)
                # there is a header
                header = next(reader)  # unused
                for row in reader:
                    domain, ip4str, ip6str = row
                    ip4, ip6 = ip4str.split(ip_delimiter), ip6str.split(ip_delimiter)
                    records[domain] = [set(ip4), set(ip6)]
                    counter = counter + 1
        except Exception as e:  # IOError
            log.warning('Exception: {0} - {1}'.format(type(e).__name__, e))
            records = None
            counter = 0

        return (records, counter)

    def resolved_available(self):
        return bool(len(self.resolved) > 0)

    def save_resolved(self, fname, delimiter=';', ip_delimiter=',', sort=True):
        """
        Writes already resolved domains to file.
        If no modifications took place during the time of last write,
        the function will immediately return.
        True    if data was successfully written.
        False   if error was encountered
        None    if no modifications happened during previous write
        """
        if delimiter == ip_delimiter:
            log.warning('Field delimiter must not be identical to IP delimiter! Using values ";" and ",").')
            delimiter = ';'
            ip_delimiter = ','

        if self.resolved.modified:
            try:
                with open(fname, mode='w', newline='') as alexafile:
                    writer = csv.writer(alexafile, delimiter=';')
                    writer.writerow(['domain', 'ip4', 'ip6'])  # header
                    if sort:
                        domainlist = sorted(list(self.resolved.keys()))
                        for domain in domainlist:
                            ip4, ip6 = self.resolved[domain]
                            row = [domain, ip_delimiter.join(ip4), ip_delimiter.join(ip6)]
                            writer.writerow(row)
                    else:
                        for domain, ips in self.resolved.items():
                            ip4, ip6 = ips
                            row = [domain, ip_delimiter.join(ip4), ip_delimiter.join(ip6)]
                            writer.writerow(row)
                log.info('Resolved data written to file [{0}]'.format(fname))
            except Exception as e:
                log.error('Error while writing file: {0} - {1}'.format(type(e).__name__, e))
                return False
            else:
                self.resolved.reset_modified()  # reset modified sentinel
                return True
        # else:
        #   log.debug('Resolved data was not modified, nothing to write')

        return None

    def save_unresolvable(self, fname, sort=True):
        """
        Save unresolvable entries (no A and/or AAAA record available).
        This allows comparison against a more recent domain file (Alexa) to check
        for new domains.
        """
        if self.unresolvable.modified:
            try:
                if sort:
                    self.unresolvable.sort()  # already modified so no problem here
                with open(fname, mode='w', newline='') as unresfile:
                    for domain in self.unresolvable:
                        unresfile.write(domain)
                        unresfile.write('\n')
                log.info('Unresolvable data written to file [{0}]'.format(fname))
            except Exception as e:
                log.error('Error while writing file: {0} - {1}'.format(type(e).__name__, e))
                return False
            else:
                self.unresolvable.reset_modified()
                return True
        # else:
        #   log.debug('Unresolvable data was not modified, nothing to write')

        return None

    def resolve_toplist(self, fname=None, force_resolution=False, write_unresolvable=False):
        """
        This function will query all entries of the top list (also the ones
        which do not have A and/or AAAA records available!).

        Resolves the top million list for A and AAAA records.
        May take a very, very long time ...
        Provide a csv with resolved domains to speed up this process.
        If any resolved data was modified everything will be written to fname.

        fname   save resolved file to given file name
                (if None use const.BASE_DIRECTORY/const.ALEXA_RESOLVED_FILE_NAME)
        force_resolution    forces the name resolution rather an entry was found
        write_unresolvable  saves the unresolvable domains to join(dirname(fname),
                            const.ALEXA_UNRESOLVABLE_FILE_NAME)
        """
        if not self.toplist:
            log.warning('Alexa Top Million List not loaded (use load_toplist_file() first), aborting ...')
            return

        try:
            counter = 0
            for _, domain in self.toplist.items():
                counter = counter + 1
                if counter % 10000 == 0:
                    log.info('Still resolving ... [{0}]'.format(counter))

                if domain in self.resolved and not force_resolution:
                    continue
                else:  # resolve
                    ips = self._resolve_host_dual(domain)
                    if ips:
                        v4, v6 = ips
                        if domain in self.resolved:  # forced to perform resolution
                            self.resolved[domain][0].update(v4)
                            self.resolved[domain][1].update(v6)
                        else:
                            self.resolved[domain] = [v4, v6]
                    else:
                        self.unresolvable.append(domain)
            log.info('Finished name resolution')
        except Exception as e:
            log.error('Exception: {0} - {1}'.format(type(e).__name__, e))
            # override fname to indicate an incomplete resolved file
            if fname:
                base_path = os.path.dirname(fname)
                fname = os.path.join(base_path, const.ALEXA_RESOLVED_FILENAME_ERRORCASE)
            else:
                fname = os.path.join(const.BASE_DIRECTORY, const.ALEXA_RESOLVED_FILENAME_ERRORCASE)
        except (KeyboardInterrupt, SystemExit):  # necessary to provide error case file name if none is given
            # override fname to indicate an incomplete resolved file
            if fname:
                base_path = os.path.dirname(fname)
                fname = os.path.join(base_path, const.ALEXA_RESOLVED_FILENAME_ERRORCASE)
            else:
                fname = os.path.join(const.BASE_DIRECTORY, const.ALEXA_RESOLVED_FILENAME_ERRORCASE)
            raise  # of course stop execution in that case
        finally:  # do this to write data although KeyboardInterrupt or SystemExit was requested
            if not fname:
                fname = os.path.join(const.BASE_DIRECTORY, const.ALEXA_RESOLVED_FILE_NAME)
            self.save_resolved(fname)  # write already resolved domains to file

            if write_unresolvable:
                if const.ALEXA_RESOLVED_FILENAME_ERRORCASE in fname:  # now we know it's an error case
                    fname = os.path.join(os.path.dirname(fname), const.ALEXA_UNRESOLVABLE_FILENAME_ERRORCASE)
                else:
                    fname = os.path.join(os.path.dirname(fname), const.ALEXA_UNRESOLVABLE_FILE_NAME)
                self.save_unresolvable(fname)

    def construct_targets(self, one_per_domain=False):
        """
        Constructs target array [(domain(s), ip4, ip6)] for all IPs per domain.
        If one_per_domain is True, one randomly chosen IPv4 and IPv6 will be
        used as target for one domain.
        Uses the resolved dict of the instance.
        """
        # TODO: This seems to do the same thing as construct_candidates() - merge these?
        if not self.resolved:
            return None

        log.info('Started target construction')

        targets = {}  # { (ip4, ip6): [ domains ] }
        for domain, ips in self.resolved.items():  # { domain: ([ips4], [ips6]) }
            ips4, ips6 = list(ips[0]), list(ips[1])
            if one_per_domain:
                rnd4 = random.sample(range(len(ips4), len(ips4)))
                rnd6 = random.sample(range(len(ips6), len(ips6)))
                for i in range(rnd4):
                    ip4_index = rnd4[i]
                    if libtools.is_global(ips4[ip4_index]):
                        ip4 = ips4[ip4_index]
                        break
                for i in range(rnd6):
                    ip6_index = rnd6[i]
                    if libtools.is_global(ips6[ip6_index]):
                        ip6 = ips4[ip6_index]
                        break
                if (ip4, ip6) in targets:
                    targets[(ip4, ip6)].append(domain)
                else:
                    targets[(ip4, ip6)] = [domain]
            else:
                glbl_res4 = libtools.is_global(ips4, ipversion=4)
                glbl_res6 = libtools.is_global(ips6, ipversion=6)
                valid4 = [ip for ip, valid in zip(ips4, glbl_res4) if valid]
                valid6 = [ip for ip, valid in zip(ips6, glbl_res6) if valid]

                if not valid4 or not valid6:  # skip this domain -> no global valid IP pair
                    continue

                for ip4, ip6 in [(x, y) for x in valid4 for y in valid6]:
                    if (ip4, ip6) in targets:
                        targets[(ip4, ip6)].append(domain)
                    else:
                        targets[(ip4, ip6)] = [domain]

        targets_prepared = []
        for ips, domains in targets.items():
            targets_prepared.append((domains, ips[0], ips[1]))

        return targets_prepared

    def construct_candidates(self, one_per_domain=False):
        """
        Constructs a CandidatePairs dict { (ip4, ip6): CandidatePair } for all IPs
        per domain. If one_per_domain is True, one randomly chosen IPv4 and IPv6
        will be used as CandidatePair.
        Uses the resolved dict of the instance.
        """
        if not self.resolved:
            return None

        candidates = {}  # { (ip4, ip6): CandidatePair }
        for domain, ips in self.resolved.items():
            ips4, ips6 = ips
            if one_per_domain:
                ip4 = list(ips4)[random.randrange(len(ips4))]
                ip6 = list(ips6)[random.randrange(len(ips6))]
                if (ip4, ip6) in candidates:  # may happen ...
                    candidates[(ip4, ip6)].add_domain(domain)
                else:
                    cp = CandidatePair(ip4, ip6, domains=[domain])
                    candidates[(ip4, ip6)] = cp
            else:
                for ip4, ip6 in [(x, y) for x in ips4 for y in ips6]:
                    if (ip4, ip6) in candidates:
                        candidates[(ip4, ip6)].add_domain(domain)
                    else:
                        cp = CandidatePair(ip4, ip6, domains=[domain])
                        candidates[(ip4, ip6)] = cp

        return candidates

    @staticmethod
    def load_remote_toplist(directory, url=const.ALEXA_URL, fname=const.ALEXA_FILE_NAME):
        """
        Load the current Alexa Top Million zip file from ALEXA_URL and extracts it to directory.
        """
        try:
            result = None
            httpresponse = urllib.request.urlopen(url)
            with zipfile.ZipFile(io.BytesIO(httpresponse.read())) as zf:
                result = zf.extract(fname, path=directory)
        except Exception as e:
            log.error('Exception: {0} - {1}'.format(type(e).__name__, e))
            return False
        else:
            return result
