import re

from retrie.trie import Trie

from ipsiblings import liblog

log = liblog.get_root_logger()


class SkipList:
    """Handles a skip-list of IP addresses to ignore per address family."""

    def __init__(self, filename):
        self.rev4, self.rev6 = self._make_regexes(filename)

    def _make_regexes(self, filename):
        """
        Returns the compiled regex objects constructed from the given file.
        """
        if not filename:
            return None, None

        v4ignore, v6ignore = parse_ignore_file(filename)

        trie = Trie()
        for v4a in v4ignore:
            a = v4a.strip().strip('*').lower()
            trie.add(a)
        v4regex = re.compile(r'^' + trie.pattern(), re.IGNORECASE)

        trie = Trie()
        for v6a in v6ignore:
            a = v6a.strip().strip('*').lower()
            trie.add(a)
        v6regex = re.compile(r'^' + trie.pattern(), re.IGNORECASE)

        return v4regex, v6regex

    def matches_pair(self, ip4, ip6):
        match4 = self.matches_v4(ip4)
        match6 = self.matches_v6(ip6)
        if match4 and match6:
            log.info('IPv4 and IPv6 blacklisted: {0} / {1}'.format(ip4, ip6))
            return True
        elif match4:
            log.info('IPv4 blacklisted: {0} / {1}'.format(ip4, ip6))
            return True
        elif match6:
            log.info('IPv6 blacklisted: {0} / {1}'.format(ip4, ip6))
            return True
        else:
            return False

    def matches_v4(self, ip4):
        return self.rev4 and self.rev4.match(ip4)

    def matches_v6(self, ip6):
        return self.rev6 and self.rev6.match(ip6)


def parse_ignore_file(file):
    """
    File structure:
    IPv4 address
    IPv4 address
    ...
    =
    IPv6 address
    ...

    The input file can use '#' for comments.
    A line starting with '=' signals the start of IPv6 addresses.
    '10.*' may be used to ignore all addresses starting with '10.x.x.x'.
    Empty lines will be ignored.
    """

    v4addresses = []
    v6addresses = []

    regex = re.compile('^([0-9]|[f:])')

    with open(file, "r") as ignore_file:
        tmp_list = v4addresses
        for line in ignore_file:
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            if line.startswith("="):
                tmp_list = v6addresses
                continue

            if re.match(regex, line):
                tmp_list.append(line)

    return v4addresses, v6addresses


NO_SKIPS = SkipList(None)
