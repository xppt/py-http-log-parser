import argparse
import json
import sys
from contextlib import ExitStack

from http_log_parser.nginx_parser import nginx_parser


def main(arg_list=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-query', action='store_true', default=False)
    parser.add_argument('file', default='-')
    args = parser.parse_args(arg_list)

    log_parser = nginx_parser(not args.no_query)

    with ExitStack() as stack:
        if args.file == '-':
            file = sys.stdin.buffer
        else:
            file = stack.enter_context(open(args.file, 'rb'))

        try:
            for line in file:
                parsed_line = log_parser(line)
                output_line = json.dumps(parsed_line) + '\n'

                try:
                    sys.stdout.buffer.write(output_line.encode('utf-8'))
                except OSError:
                    print('write error', file=sys.stderr)
                    sys.exit(2)

        except KeyboardInterrupt:
            sys.exit(1)
