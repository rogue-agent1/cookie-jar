#!/usr/bin/env python3
"""cookie_jar - HTTP cookie parser, builder, and jar management."""
import sys, time

class Cookie:
    def __init__(self, name, value, domain="", path="/", expires=None, secure=False, httponly=False, samesite=""):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.expires = expires
        self.secure = secure
        self.httponly = httponly
        self.samesite = samesite

    def is_expired(self, now=None):
        if self.expires is None:
            return False
        return (now or time.time()) > self.expires

    def to_set_header(self):
        parts = [f"{self.name}={self.value}"]
        if self.domain: parts.append(f"Domain={self.domain}")
        if self.path != "/": parts.append(f"Path={self.path}")
        if self.secure: parts.append("Secure")
        if self.httponly: parts.append("HttpOnly")
        if self.samesite: parts.append(f"SameSite={self.samesite}")
        return "; ".join(parts)

    @staticmethod
    def parse_set_cookie(header):
        parts = header.split("; ")
        nv = parts[0].split("=", 1)
        name, value = nv[0], nv[1] if len(nv) > 1 else ""
        kwargs = {"name": name, "value": value}
        for part in parts[1:]:
            if "=" in part:
                k, v = part.split("=", 1)
                k = k.lower()
                if k == "domain": kwargs["domain"] = v
                elif k == "path": kwargs["path"] = v
                elif k == "samesite": kwargs["samesite"] = v
            else:
                p = part.lower()
                if p == "secure": kwargs["secure"] = True
                elif p == "httponly": kwargs["httponly"] = True
        return Cookie(**kwargs)

class CookieJar:
    def __init__(self):
        self.cookies = {}

    def set(self, cookie):
        self.cookies[(cookie.domain, cookie.path, cookie.name)] = cookie

    def get(self, domain, path="/"):
        result = {}
        for (d, p, n), c in self.cookies.items():
            if (not d or domain.endswith(d)) and path.startswith(p) and not c.is_expired():
                result[n] = c.value
        return result

    def to_header(self, domain, path="/"):
        cookies = self.get(domain, path)
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def clear_expired(self):
        now = time.time()
        self.cookies = {k: v for k, v in self.cookies.items() if not v.is_expired(now)}

def test():
    c = Cookie.parse_set_cookie("session=abc123; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Strict")
    assert c.name == "session"
    assert c.value == "abc123"
    assert c.domain == ".example.com"
    assert c.secure and c.httponly
    assert c.samesite == "Strict"
    jar = CookieJar()
    jar.set(Cookie("sid", "xyz", domain=".example.com"))
    jar.set(Cookie("lang", "en", domain=".example.com"))
    jar.set(Cookie("other", "val", domain=".other.com"))
    cookies = jar.get("www.example.com")
    assert cookies["sid"] == "xyz"
    assert cookies["lang"] == "en"
    assert "other" not in cookies
    header = jar.to_header("www.example.com")
    assert "sid=xyz" in header
    expired = Cookie("old", "val", expires=0)
    assert expired.is_expired()
    jar.set(expired)
    jar.clear_expired()
    s = c.to_set_header()
    assert "session=abc123" in s
    assert "Secure" in s
    print("All tests passed!")

if __name__ == "__main__":
    test() if "--test" in sys.argv else print("cookie_jar: Cookie management. Use --test")
