from grAPI.core import is_potential_api

def test_is_potential_api():
    assert is_potential_api("/api/users")
    assert is_potential_api("https://example.com/graphql")
    assert not is_potential_api("https://example.com/home")
    assert is_potential_api("/v1/data")
