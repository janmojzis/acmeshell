try:
        from urllib.request import urlopen
        from urllib.request import Request
        from urllib.error   import HTTPError
except ImportError:
        from urllib2 import urlopen
        from urllib2 import Request
        from urllib2 import HTTPError

def httpquery(url = "", data = None, headers = {}, timeout = 60):
        """
        python2/3 compatible HTTP/HTTPS client
        """

        try:
                req = Request(url, data = data, headers = headers)
                r = urlopen(req, timeout = timeout)
        except HTTPError as e:
                r = e
        except Exception as e:
                return { "status": -1, "error": str(e) }

        headers = {}
        for h, v in r.info().items():
                headers[h.lower()] = v

        return {
                "status": r.code,
                "error": "http error %d %s" % (r.code, r.msg),
                "headers": headers,
                "body": r.read()
        }
