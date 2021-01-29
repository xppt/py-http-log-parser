import unittest

from http_log_parser.nginx_parser import NginxParser


class NginxParserTestCase(unittest.TestCase):
    def test_nginx_parser(self):
        parser = NginxParser()

        log_line = (
            b'1.2.3.4 - - [18/Jun/2020:00:01:09 +0300] "GET /path/?greetings=hello%20world'
            b' HTTP/1.1" 204 0 "https://example.com/" "Chrome/1 Firefox/2 IE/3 Edge/4"'
        )

        self.assertEqual(parser(log_line), {
            'ip': '1.2.3.4',
            'ts': 1592427669,
            'method': 'GET',
            'path': '/path/',
            'query': {'greetings': 'hello world'},
            'status': 204,
            'size': 0,
            'referer': 'https://example.com/',
            'user_agent': 'Chrome/1 Firefox/2 IE/3 Edge/4',
        })
