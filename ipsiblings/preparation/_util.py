import sys

from ipsiblings import logsetup

log = logsetup.get_root_logger()


def _prepare_reduce(iterable, conf, what):
    should_reduce = (conf.start_index or conf.end_index)
    if not iterable or not should_reduce:
        return False
    inp_len = len(iterable)
    if conf.end_index is None or conf.end_index > inp_len:
        conf.end_index = inp_len
    if conf.start_index >= conf.end_index:
        log.error(f'{what} - Start index must be less than end index ({conf.start_index} to {conf.end_index})')
        sys.exit(-6)
    elif conf.start_index >= inp_len:
        log.error(f'{what} - Start index exceeds available input ({conf.start_index} >= {inp_len}')
        sys.exit(-6)
    else:
        return True


def _reduce_map(inp_dict, conf, what):
    # Python 3.6+ preserves insertion order with built-in dict
    if not _prepare_reduce(inp_dict, conf, what):
        return inp_dict
    original_len = len(inp_dict)
    keys = list(inp_dict.keys())[conf.start_index: conf.end_index]
    result = {key: inp_dict[key] for key in keys}
    log.info(f'Reduced loaded {what} from size [{original_len}] to [{len(result)}] '
             f'(indices [{conf.start_index}] to [{conf.end_index}])')
    return result


def _reduce_list(inp_list, conf, what):
    if not _prepare_reduce(inp_list, conf, what):
        return inp_list
    original_len = len(inp_list)
    result = inp_list[conf.start_index: conf.end_index]
    log.info(f'Reduced loaded {what} from size [{original_len}] to [{len(result)}] '
             f'(indices [{conf.start_index}] to [{conf.end_index}])')
    return result
