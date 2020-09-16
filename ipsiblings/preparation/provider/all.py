from ipsiblings.preparation.provider.bitcoin import BitcoinNodesProvider
from ipsiblings.preparation.provider.filesystem import FilesystemProvider

# NOTE: When adding a new option here, also add it to the allowed providers in config.args
# We cannot just access the keys from here because we don't want the config module depending
# on an implementation
PROVIDERS = {
    'bitcoin': BitcoinNodesProvider(),
    'filesystem': FilesystemProvider()
}


def get_provider(key):
    if key in PROVIDERS:
        return PROVIDERS[key.lower()]
    else:
        raise ValueError('No target provider with name \'{0}\' found!'.format(key))


def get_provider_names():
    return PROVIDERS.keys()
