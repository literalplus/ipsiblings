from ipsiblings.targetprovider.alexa import AlexaProvider

PROVIDERS = {
    'alexa': AlexaProvider(),
}


def get_provider(key):
    if key in PROVIDERS:
        return PROVIDERS[key.lower()]
    else:
        raise ValueError('No target provider with name \'{0}\' found!'.format(key))


def get_provider_names():
    return PROVIDERS.keys()
