import unittest
from unittest import mock

from zappa.cli import ZappaCLI
from zappa.core import Zappa


class BrycesTest(unittest.TestCase):

    # Test that when we don't pass any SSE settings in that the S3 ExtraArgs
    # is the expected None
    @mock.patch("botocore.client")
    def test_s3_extra_args(self, *_):
        boto_mock = mock.MagicMock()
        zappa = Zappa(
            boto_session=boto_mock,
            profile_name="test",
            aws_region="test",
            load_credentials=False,
        )
        # zappa.set_s3_extra_args(None, None)
        assert zappa.extra_s3_args is None
        assert zappa is not None

    # Now test that a KMS key without Server Side Encryption ExtraArgs is still
    # None
    @mock.patch("botocore.client")
    def test_s3_sse_kms_key_id(self, *_):
        boto_mock = mock.MagicMock()
        zappa = Zappa(
            boto_session=boto_mock,
            profile_name="test",
            aws_region="test",
            load_credentials=True,
            aws_s3_sse=None,
            aws_s3_sse_kms_key_id="arn:aws:kms:us-east-1:012345678910:key/abcdef01-2345-6789-0abc-def012345678",
        )
        expected = None
        self.assertEqual(zappa.extra_s3_args, expected)

    # Now test that passing just the SSE sets ServerSideEncryption in ExtraArgs
    @mock.patch("botocore.client")
    def test_s3_sse(self, *_):
        boto_mock = mock.MagicMock()
        zappa = Zappa(
            boto_session=boto_mock, profile_name="test", aws_region="test", load_credentials=True, aws_s3_sse="aws:kms"
        )
        expected = {"ServerSideEncryption": "aws:kms"}
        self.assertEqual(zappa.extra_s3_args, expected)

    # Now test that both SSE & KMS key being set gets into ExtraArgs properly
    @mock.patch("botocore.client")
    def test_sse_all(self, *_):
        boto_mock = mock.MagicMock()
        zappa = Zappa(
            boto_session=boto_mock,
            profile_name="test",
            aws_region="test",
            load_credentials=True,
            aws_s3_sse="aws:kms",
            aws_s3_sse_kms_key_id="arn:aws:kms:us-east-1:012345678910:key/abcdef01-2345-6789-0abc-def012345678",
        )
        expected = {
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": "arn:aws:kms:us-east-1:012345678910:key/abcdef01-2345-6789-0abc-def012345678",
        }
        self.assertEqual(zappa.extra_s3_args, expected)

    # Also test that the transition from settings file into ExtraArgs works
    # as expected
    @mock.patch("botocore.client")
    def test_sse_settings(self, *_):
        boto_mock = mock.MagicMock()
        zappa_cli = ZappaCLI()
        zappa_cli.api_stage = "sse"
        zappa_cli.load_settings("tests/test_sse_settings.json", boto_mock)
        expected = {
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": "arn:aws:kms:us-east-1:012345678910:key/abcdef01-2345-6789-0abc-def012345678",
        }
        self.assertEqual(zappa_cli.zappa.extra_s3_args, expected)
