from enum import Enum

PRIMARY_DELIMITER = '\t'
SECONDARY_DELIMITER = ','
TERTIARY_DELIMITER = ':'
NONE_MARKER = '--None--'


class TargetProviderChoice(Enum):
    BITCOIN = 'bitcoin'
    FILESYSTEM = 'filesystem'

    @classmethod
    def all_keys(cls):
        return [it.name for it in cls]

    @classmethod
    def default(cls):
        return cls.BITCOIN


class EvaluatorChoice(Enum):
    TCPRAW_SCHEITLE = 'tcpraw-scheitle'
    TCPRAW_STARKE = 'tcpraw-starke'
    DOMAIN = 'validate-domain'
    SSH_KEYSCAN = 'validate-ssh-keyscan'
    TCP_OPTIONS = 'tcp-options'
    ML_STARKE = 'machine-learning-starke'

    @classmethod
    def all_keys(cls):
        return [it.name for it in cls]


class HarvesterChoice(Enum):
    TCP_TS = 'tcp-ts'
    BTC = 'btc'

    @classmethod
    def all_keys(cls):
        return [it.name for it in cls]
