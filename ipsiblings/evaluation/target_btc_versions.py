from collections import defaultdict
from typing import Tuple, Dict, List

from ipsiblings.harvesting.btc.export import BtcImporter
from ipsiblings.model import Target


class TargetBtcVersions:
    def __init__(self, base_dir: str):
        ip_filter = None
        self.target_versions_map: Dict[Tuple[int, str], List[Tuple[int, str]]] = defaultdict(list)
        for conn in BtcImporter(base_dir).yield_relevant(ip_filter):
            key = (conn.ip_ver, conn.ip)
            versions_for_this_target = self.target_versions_map[key]
            ver_tup = (conn.ver_info.proto_ver, conn.ver_info.sub_ver)
            if ver_tup not in versions_for_this_target:
                versions_for_this_target.append(ver_tup)

    def get_version_tuple(self, target: Target) -> List[Tuple[int, str]]:
        return self.target_versions_map.get((target.ip_version, target.address))

    def is_match_possible(self, target4: Target, target6: Target):
        version4 = self.get_version_tuple(target4)
        version6 = self.get_version_tuple(target6)
        if not version4 and not version6:
            # need to group all without info
            return True
        elif len(version4) != len(version6):
            # If they upgrade, we assume that we will observe both versions in the same order for both protocols
            return False
        else:
            for (proto_ver4, user_agent4) in version4:
                for (proto_ver6, user_agent6) in version6:
                    if proto_ver4 != proto_ver6 or version4 != version6:
                        return False
            return True
