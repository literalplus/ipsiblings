import os
import sys

from ipsiblings.config.args import parser


def print_usage_and_exit(message):
    parser.print_usage(sys.stderr)
    basename = os.path.basename(sys.argv[0])
    sys.stderr.write(f'{basename}: error: {message}\n')
    sys.exit(2)
