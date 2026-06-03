"""Tests for resource-identifier masking."""

from src.masking import mask_text


def test_masks_named_resource():
    out = mask_text("Bucket 'my-secret-bucket' is public", names=["my-secret-bucket"])
    assert "my-secret-bucket" not in out
    assert "<resource:" in out


def test_preserves_arn_skeleton():
    out = mask_text("arn:aws:s3:::my-secret-bucket", names=["my-secret-bucket"])
    assert out.startswith("arn:aws:s3:::")
    assert "my-secret-bucket" not in out


def test_masks_account_id():
    out = mask_text("Account 123456789012 owns this")
    assert "123456789012" not in out
    assert "<account:" in out


def test_masks_security_group_id():
    out = mask_text("Group sg-05570f8ed81143574 exposes SSH")
    assert "sg-05570f8ed81143574" not in out
    assert "<sg:" in out


def test_masks_instance_and_access_key():
    out = mask_text("i-0abc1234def567890 with key AKIAIOSFODNN7EXAMPLE")
    assert "i-0abc1234def567890" not in out
    assert "AKIAIOSFODNN7EXAMPLE" not in out


def test_alias_is_deterministic():
    a = mask_text("arn:aws:s3:::b", names=["b"])
    b = mask_text("arn:aws:s3:::b", names=["b"])
    assert a == b


def test_empty_text_is_safe():
    assert mask_text("") == ""
    assert mask_text("no identifiers here") == "no identifiers here"
