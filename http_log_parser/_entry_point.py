import argparse
import json
import os
import sys
from contextlib import ExitStack, contextmanager
from typing import Sequence, Iterator

from http_log_parser.nginx_parser import LineParseError, NginxParser


def main(arg_list=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-query', action='store_true', default=False)
    parser.add_argument('--skip-errors', action='store_true', default=False)
    parser.add_argument('files', nargs='*')
    args = parser.parse_args(arg_list)

    log_parser = NginxParser(not args.no_query)

    files = args.files or ['-']

    try:
        for line in _cat_files(files):
            try:
                parsed_line = log_parser(line)
            except LineParseError:
                print('malformed:', repr(line), file=sys.stderr)

                if args.skip_errors:
                    continue
                else:
                    sys.exit(3)

            output_line = json.dumps(parsed_line)

            with _handle_write_errors():
                print(output_line, flush=True)
    except KeyboardInterrupt:
        sys.exit(1)


def _cat_files(files: Sequence[str]) -> Iterator[bytes]:
    for filename in files:
        with ExitStack() as stack:
            if filename == '-':
                file = sys.stdin.buffer
            else:
                file = stack.enter_context(open(filename, 'rb'))

            yield from file


@contextmanager
def _handle_write_errors():
    try:
        yield
    except BrokenPipeError:
        if os.name == 'posix':
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())

        sys.exit(1)
    except OSError as e:
        print('write error', e.errno, file=sys.stderr)
        sys.exit(2)
