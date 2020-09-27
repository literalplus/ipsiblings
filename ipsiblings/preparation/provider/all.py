from ipsiblings.model import const
from ipsiblings.preparation.provider.bitcoin import BitcoinNodesProvider
from ipsiblings.preparation.provider.filesystem import FilesystemProvider

# NOTE: When adding a new option here, also add it to the allowed providers in model.const
# We cannot just access the keys from here because we don't want the config module depending
# on an implementation
PROVIDERS = {
    const.TargetProviderChoice.BITCOIN: BitcoinNodesProvider(),
    const.TargetProviderChoice.FILESYSTEM: FilesystemProvider()
}


def get_provider(key: const.TargetProviderChoice):
    if key in PROVIDERS:
        return PROVIDERS[key]
    else:
        raise AssertionError(f'Target provider {key} is not registered!')
