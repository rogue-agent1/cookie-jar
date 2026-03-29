#!/usr/bin/env python3
"""HTTP cookie parser and jar. Zero dependencies."""
import time, sys, re

class Cookie:
    def __init__(self, name, value, domain="", path="/", expires=None,
                 secure=False, httponly=False, samesite=""):
        self.name = name; self.value = value; self.domain = domain
        self.path = path; self.expires = expires
        self.secure = secure; self.httponly = httponly; self.samesite = samesite

    def is_expired(self):
        if self.expires is None: return False
        return time.time() > self.expires

    def __repr__(self):
        return f"{self.name}={self.value}"

class CookieJar:
    def __init__(self):
        self.cookies = []

    def add(self, cookie):
        self.cookies = [c for c in self.cookies if not (c.name == cookie.name and c.domain == cookie.domain)]
        self.cookies.append(cookie)

    def get(self, name, domain=None):
        for c in self.cookies:
            if c.name == name and not c.is_expired():
                if domain is None or c.domain == domain or domain.endswith(c.domain):
                    return c
        return None

    def for_url(self, url):
        from url_parse import URL as _  # avoid dep — inline parse
        # Simple domain extraction
        domain = url.split("://")[-1].split("/")[0].split(":")[0]
        path = "/" + url.split("://")[-1].split("/", 1)[-1] if "/" in url.split("://")[-1] else "/"
        result = []
        for c in self.cookies:
            if c.is_expired(): continue
            if c.domain and not domain.endswith(c.domain.lstrip(".")): continue
            if not path.startswith(c.path): continue
            result.append(c)
        return result

    def header(self, url):
        cookies = self.for_url(url)
        return "; ".join(f"{c.name}={c.value}" for c in cookies)

    def parse_set_cookie(self, header, domain=""):
        parts = header.split(";")
        name_val = parts[0].strip()
        if "=" not in name_val: return
        name, value = name_val.split("=", 1)
        cookie = Cookie(name.strip(), value.strip(), domain=domain)
        for part in parts[1:]:
            part = part.strip().lower()
            if part.startswith("domain="):
                cookie.domain = part[7:]
            elif part.startswith("path="):
                cookie.path = part[5:]
            elif part == "secure":
                cookie.secure = True
            elif part == "httponly":
                cookie.httponly = True
            elif part.startswith("samesite="):
                cookie.samesite = part[9:]
            elif part.startswith("max-age="):
                try: cookie.expires = time.time() + int(part[8:])
                except: pass
        self.add(cookie)

    def clear(self):
        self.cookies.clear()

    def __len__(self):
        return len([c for c in self.cookies if not c.is_expired()])

if __name__ == "__main__":
    jar = CookieJar()
    jar.parse_set_cookie("session=abc123; Path=/; HttpOnly; Secure", domain="example.com")
    jar.parse_set_cookie("theme=dark; Path=/; Max-Age=3600", domain="example.com")
    print(f"Cookies: {len(jar)}")
    print(f"Header: {jar.header('https://example.com/page')}")
