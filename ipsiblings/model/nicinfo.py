class NicInfo:
    def __init__(self, name: str, mac: str, ip4: str, ip6: str):
        self.name = name
        self.mac: str = mac.lower()
        self.ip4: str = ip4
        self.ip6: str = ip6.lower() if ip6 else "???"

    def __str__(self):
        return f'NicInfo({self.name}: mac={self.mac}, ip4={self.ip4}, ip6={self.ip6})'
