from cookie_jar import CookieJar, Cookie
jar = CookieJar()
jar.parse_set_cookie("session=abc; Path=/; HttpOnly", domain="example.com")
jar.parse_set_cookie("theme=dark; Path=/", domain="example.com")
assert len(jar) == 2
assert jar.get("session").value == "abc"
h = jar.header("https://example.com/page")
assert "session=abc" in h
assert "theme=dark" in h
print("Cookie jar tests passed")