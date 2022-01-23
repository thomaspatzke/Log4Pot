from log4pot.payloader import Payloader
import pytest

@pytest.fixture
def payloader():
    return Payloader()

def test_url_extraction(payloader : Payloader):
    payload = b"foobar http://test.invalid/ String.fromCharCode(102,111,111,98,97,114,32,104,116,116,112,58,47,47,111,98,102,117,115,99,97,116,101,100,46,105,110,118,97,108,105,100,47)"
    assert payloader.extract_urls_from_payload(payload) == {
        "http://test.invalid/",
        "http://obfuscated.invalid/",
    }