#!/usr/bin/env python3
"""cookie_jar - HTTP cookie parser and jar with domain/path matching."""
import sys, time

class Cookie:
    def __init__(self, name, value, domain="", path="/", expires=None, secure=False, httponly=False):
        self.name, self.value = name, value
        self.domain, self.path = domain, path
        self.expires, self.secure, self.httponly = expires, secure, httponly

class CookieJar:
    def __init__(self):
        self.cookies = []
    def add(self, cookie):
        self.cookies = [c for c in self.cookies if not (c.name == cookie.name and c.domain == cookie.domain and c.path == cookie.path)]
        self.cookies.append(cookie)
    def get(self, domain, path="/", secure=False):
        result = []
        now = time.time()
        for c in self.cookies:
            if c.expires and c.expires < now: continue
            if c.domain and not domain.endswith(c.domain): continue
            if not path.startswith(c.path): continue
            if c.secure and not secure: continue
            result.append(c)
        return result
    def parse_set_cookie(self, header, domain=""):
        parts = header.split(";")
        nv = parts[0].strip().split("=", 1)
        name, value = nv[0], nv[1] if len(nv) > 1 else ""
        c = Cookie(name, value, domain=domain)
        for attr in parts[1:]:
            attr = attr.strip().lower()
            if attr.startswith("domain="):
                c.domain = attr.split("=", 1)[1]
            elif attr.startswith("path="):
                c.path = attr.split("=", 1)[1]
            elif attr == "secure":
                c.secure = True
            elif attr == "httponly":
                c.httponly = True
        self.add(c)
        return c

def test():
    jar = CookieJar()
    jar.parse_set_cookie("sid=abc123; Domain=.example.com; Path=/; Secure; HttpOnly")
    jar.parse_set_cookie("theme=dark; Path=/")
    cookies = jar.get("www.example.com", "/page", secure=True)
    assert any(c.name == "sid" and c.value == "abc123" for c in cookies)
    insecure = jar.get("www.example.com", "/page", secure=False)
    assert not any(c.name == "sid" for c in insecure)
    jar.parse_set_cookie("sid=updated; Domain=.example.com; Path=/; Secure")
    cookies2 = jar.get("www.example.com", "/", secure=True)
    sids = [c for c in cookies2 if c.name == "sid"]
    assert len(sids) == 1 and sids[0].value == "updated"
    print("cookie_jar: all tests passed")

if __name__ == "__main__":
    test() if "--test" in sys.argv else print("Usage: cookie_jar.py --test")
