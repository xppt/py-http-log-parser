import datetime
import re
import urllib.parse

_unescape_pattern = re.compile(r'\\x([0-9a-z]{2})'.encode('ascii'), re.IGNORECASE)


def _nginx_unescape(value: bytes) -> bytes:
    def replace_char(match):
        return bytes.fromhex(match.group(1).decode('ascii'))

    return _unescape_pattern.sub(replace_char, value)


_log_pattern = re.compile(
    r'''^
    ([\d.]+)[ ] # IP
    (\S+)[ ] # dash (in combined) or hostname
    (\S+)[ ] # user
    \[([^\]]+)\][ ] # time
    "
        ([A-Z]+)[ ]  # method
        ([^"\s]+)[ ] # url
        ([^"])+      # proto
    "[ ]
    (\d+)[ ]    # status
    (\d+)       # size
    '''.encode('ascii'), re.VERBOSE)


def _decode_ascii(value: bytes) -> str:
    return _nginx_unescape(value).decode('ascii')


def _decode_host(value: bytes) -> str:
    return _nginx_unescape(value).decode('idna')


def _decode_noop(value):
    return value


_nginx_months = [
    b'Jan',
    b'Feb',
    b'Mar',
    b'Apr',
    b'May',
    b'Jun',
    b'Jul',
    b'Aug',
    b'Sep',
    b'Oct',
    b'Nov',
    b'Dec',
]

_nginx_time_pattern = re.compile(
    r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})'.encode('ascii'))

_last_decoded_ts_bytes = None
_last_decoded_ts_result = 0


def _decode_ts(value: bytes) -> int:
    """ngx_times.c"""

    global _last_decoded_ts_bytes, _last_decoded_ts_result

    if _last_decoded_ts_bytes == value:
        return _last_decoded_ts_result

    sday, smon, syear, shour, smin, ssec, off_sign, off_hours, off_minutes \
        = _nginx_time_pattern.fullmatch(value).groups()

    local_ts = datetime.datetime(
        year=int(syear),
        month=_nginx_months.index(smon) + 1,
        day=int(sday),
        hour=int(shour),
        minute=int(smin),
        second=int(ssec),
    )

    offset = datetime.timedelta(hours=int(off_hours), minutes=int(off_minutes))
    if off_sign == '-':
        offset = -offset

    result = _utc_dt_timestamp(local_ts - offset)

    _last_decoded_ts_bytes = value
    _last_decoded_ts_result = result

    return result


_log_decoders = (
    _decode_ascii,  # IP
    _decode_host,   # hostname or dash
    _decode_noop,   # user
    _decode_ts,     # time
    _decode_noop,   # method
    _decode_ascii,  # url
    _decode_noop,   # proto
    int,            # status
    int,            # size
)


_UNIX_EPOCH = datetime.datetime(1970, 1, 1)


def _utc_dt_timestamp(dt: datetime.datetime) -> int:
    assert dt.tzinfo is None
    return int((dt - _UNIX_EPOCH).total_seconds())


def nginx_parser(parse_query=True):
    def parse_nginx_line(line: bytes):
        match = _log_pattern.search(line)
        if match is None:
            raise ValueError('Line is malformed')

        values = (
            decoder(bytes_val)
            for bytes_val, decoder in zip(match.groups(), _log_decoders)
        )
        ip, host, _user, ts, _method, url, _proto, status, size = values

        parsed_url = urllib.parse.urlparse(url)

        row = {
            'status': status,
            'ip': ip,
            'ts': ts,
            'path': parsed_url.path,
            'size': size,
        }

        if host != '-':
            row['host'] = host

        if parse_query:
            row['query'] = {
                key: value for key, value in urllib.parse.parse_qsl(parsed_url.query)
            }
        else:
            row['query'] = parsed_url.query

        return row

    return parse_nginx_line
