class BusinessException(Exception):
    """Thrown if a business error requires the program execution to abort"""
    pass


class ConfigurationException(BusinessException):
    """Thrown if a configuration error is encountered"""
    pass


class DataException(BusinessException):
    """Thrown if invalid data is encountered"""
    pass


class JustExit(Exception):
    """Thrown if an early non-error exit was requested, preventing further execution"""
    pass


class SiblingEvaluationError(Exception):
    def __init__(self, sibling_status=None):
        self.sibling_status = sibling_status
