from isms_pii_toolkit.crypto import decrypt_text, encrypt_text


def test_encrypt_and_decrypt_round_trip() -> None:
    key = "b" * 64
    token = encrypt_text("secret-value", key)
    assert decrypt_text(token, key) == "secret-value"
