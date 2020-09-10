class ConfigurationException(Exception):
    """Thrown if a configuration error is encountered"""
    pass


class JustExit(Exception):
    """Thrown if an early non-error exit was requested, preventing further execution"""
    pass
