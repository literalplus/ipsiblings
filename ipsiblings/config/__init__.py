from .args import print_usage_and_exit
from .model import AppConfig, FlagsConfig, GeoipConfig, PathsConfig, CandidatesConfig, TargetProviderConfig

"""
Handles configuration of the application via command-line parameters and provides this information grouped by
concern, similar to what Spring Boot does, but less fancy.
"""
