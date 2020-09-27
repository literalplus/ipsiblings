from typing import Dict, Any, Optional, Iterable

from ipsiblings import liblog
from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, FamilySpecificSiblingProperty
from ipsiblings.model import DataException

log = liblog.get_root_logger()


class KeyscanResult:
    def __init__(self, ip_version: int, ip_address: str, agent: str):
        self.ip_version = ip_version
        self.ip_address = ip_address
        self.agent = agent
        self.key_kind_to_fingerprint: Dict[str, str] = {}
        self.locked = False

    @property
    def key_kinds(self) -> Iterable[str]:
        return self.key_kind_to_fingerprint.keys()

    def lock(self):
        self.locked = True

    def register_key(self, kind: str, fingerprint: str):
        if self.locked:
            raise DataException('Cannot write to locked result')
        self.key_kind_to_fingerprint[kind] = fingerprint


class SshProperty(FamilySpecificSiblingProperty[Optional[KeyscanResult]]):
    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'SshProperty':
        return cls()

    def __init__(self):
        self.data4 = None
        self.data6 = None

    def __setitem__(self, key, value: KeyscanResult):
        if key == 4:
            self.data4 = value
        elif key == 6:
            self.data6 = value
        else:
            raise KeyError

    def has_data_for_both(self):
        return bool(self[4] and self[6])

    def do_agents_match(self) -> Optional[bool]:
        if not self.has_data_for_both():
            return None
        else:
            return self[4].agent == self[6].agent

    def do_keys_match(self) -> Optional[bool]:
        if not self.has_data_for_both():
            return None
        shared_key_kinds = set(self[4].key_kinds).intersection(self[6].key_kinds)
        if not shared_key_kinds:
            return None
        for kind in shared_key_kinds:
            if self[4].key_kind_to_fingerprint[kind] != self[6].key_kind_to_fingerprint[kind]:
                return False
        return True

    def export(self) -> Dict[str, Any]:
        return {
            'both_present': self.has_data_for_both(),
            'agents_match': self.do_agents_match(),
            'keys_match': self.do_keys_match()
        }
