from ipsiblings.targetprovider.alexa import AlexaProvider
from ipsiblings.targetprovider.bitcoin import BitcoinNodesProvider

PROVIDERS = {
    'alexa': AlexaProvider(),
    'bitcoin': BitcoinNodesProvider()
}


def get_provider(key):
    if key in PROVIDERS:
        return PROVIDERS[key.lower()]
    else:
        raise ValueError('No target provider with name \'{0}\' found!'.format(key))


def get_provider_names():
    return PROVIDERS.keys()
