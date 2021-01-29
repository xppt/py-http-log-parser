http-log-parser
===

Package supports "nginx-combined" format for now.

```
usage: http-log-parser [-h] [--no-query] [--skip-errors] [files [files ...]]

positional arguments:
  files

optional arguments:
  -h, --help     show this help message and exit
  --no-query
  --skip-errors
```

**Example**

```
$ http-log-parser /var/log/http/access.log | jq .  # jq used for pretty printing 
{
  "ip": "1.2.3.4",
  "ts": 1592427669,
  "method": "GET",
  "path": "/path/",
  "status": 204,
  "size": 0,
  "referer": "https://example.com/",
  "user_agent": "Chrome/1 Firefox/2 IE/3 Edge/4",
  "query": {
    "greetings": "hello world"
  }
}
...
```
