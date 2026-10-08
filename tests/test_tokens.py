from cardiolink_auth import issue_token, verify_token


def test_roundtrip():
    tok = issue_token({"sub": "clinician-1", "role": "clinician"})
    claims = verify_token(tok)
    assert claims["sub"] == "clinician-1"
