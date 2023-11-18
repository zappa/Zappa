import json
import os
import re
import shutil
import tempfile
import unittest
from typing import Tuple
from unittest import mock

from zappa.core import Zappa
from zappa.ext.django_zappa import get_django_wsgi
from zappa.utilities import (
    ApacheNCSAFormatter,
    InvalidAwsLambdaName,
    conflicts_with_a_neighbouring_module,
    contains_python_files_or_subdirs,
    detect_django_settings,
    detect_flask_apps,
    get_venv_from_python_version,
    human_size,
    is_valid_bucket_name,
    parse_s3_url,
    string_to_timestamp,
    titlecase_keys,
    validate_name,
)


class GeneralUtilitiesTestCase(unittest.TestCase):
    def setUp(self):
        self.sleep_patch = mock.patch("time.sleep", return_value=None)
        # Tests expect us-east-1.
        # If the user has set a different region in env variables, we set it aside for now and use us-east-1
        self.users_current_region_name = os.environ.get("AWS_DEFAULT_REGION", None)
        os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
        if not os.environ.get("PLACEBO_MODE") == "record":
            self.sleep_patch.start()

    def tearDown(self):
        if not os.environ.get("PLACEBO_MODE") == "record":
            self.sleep_patch.stop()
        del os.environ["AWS_DEFAULT_REGION"]
        if self.users_current_region_name is not None:
            # Give the user their AWS region back, we're done testing with us-east-1.
            os.environ["AWS_DEFAULT_REGION"] = self.users_current_region_name

    @mock.patch("zappa.core.find_packages")
    @mock.patch("os.remove")
    def test_copy_editable_packages(self, mock_remove, mock_find_packages):
        virtual_env = os.environ.get("VIRTUAL_ENV")
        if not virtual_env:
            return self.skipTest("test_copy_editable_packages must be run in a virtualenv")

        temp_package_dir = tempfile.mkdtemp()
        try:
            egg_links = [
                os.path.join(
                    virtual_env,
                    "lib",
                    get_venv_from_python_version(),
                    "site-packages",
                    "test-copy-editable-packages.egg-link",
                )
            ]
            egg_path = "/some/other/directory/package"
            mock_find_packages.return_value = [
                "package",
                "package.subpackage",
                "package.another",
            ]
            temp_egg_link = os.path.join(temp_package_dir, "package-python.egg-link")

            z = Zappa()
            mock_open = mock.mock_open(read_data=egg_path.encode("utf-8"))
            with mock.patch("zappa.core.open", mock_open), mock.patch("glob.glob") as mock_glob, mock.patch(
                "zappa.core.copytree"
            ) as mock_copytree:
                # we use glob.glob to get the egg-links in the temp packages
                # directory
                mock_glob.return_value = [temp_egg_link]

                z.copy_editable_packages(egg_links, temp_package_dir)

                # make sure we copied the right directories
                mock_copytree.assert_called_with(
                    os.path.join(egg_path, "package"),
                    os.path.join(temp_package_dir, "package"),
                    metadata=False,
                    symlinks=False,
                )
                self.assertEqual(mock_copytree.call_count, 1)

                # make sure it removes the egg-link from the temp packages
                # directory
                mock_remove.assert_called_with(temp_egg_link)
                self.assertEqual(mock_remove.call_count, 1)
        finally:
            shutil.rmtree(temp_package_dir)

        return

    def test_detect_dj(self):
        # Sanity
        settings_modules = detect_django_settings()

    def test_dj_wsgi(self):
        # Sanity
        settings_modules = detect_django_settings()

        settings = """
# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.7/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'alskdfjalsdkf=0*%do-ayvy*m2k=vss*$7)j8q!@u0+d^na7mi2(^!l!d'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

TEMPLATE_DEBUG = True

ALLOWED_HOSTS = []

# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'blah.urls'
WSGI_APPLICATION = 'hackathon_starter.wsgi.application'

# Database
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

# Internationalization
# https://docs.djangoproject.com/en/1.7/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True
        """

        djts = open("dj_test_settings.py", "w")
        djts.write(settings)
        djts.close()

        app = get_django_wsgi("dj_test_settings")
        try:
            os.remove("dj_test_settings.py")
            os.remove("dj_test_settings.pyc")
        except Exception as e:
            pass

    ##
    # Util / Misc
    ##

    def test_human_units(self):
        human_size(1)
        human_size(9999999999999)

    def test_string_to_timestamp(self):
        boo = string_to_timestamp("asdf")
        self.assertTrue(boo == 0)

        yay = string_to_timestamp("1h")
        self.assertTrue(type(yay) == int)
        self.assertTrue(yay > 0)

        yay = string_to_timestamp("4m")
        self.assertTrue(type(yay) == int)
        self.assertTrue(yay > 0)

        yay = string_to_timestamp("1mm")
        self.assertTrue(type(yay) == int)
        self.assertTrue(yay > 0)

        yay = string_to_timestamp("1mm1w1d1h1m1s1ms1us")
        self.assertTrue(type(yay) == int)
        self.assertTrue(yay > 0)

    def test_detect_dj(self):
        # Sanity
        settings_modules = detect_django_settings()

    def test_detect_flask(self):
        # Sanity
        settings_modules = detect_flask_apps()

    def test_s3_url_parser(self):
        remote_bucket, remote_file = parse_s3_url("s3://my-project-config-files/filename.json")
        self.assertEqual(remote_bucket, "my-project-config-files")
        self.assertEqual(remote_file, "filename.json")

        remote_bucket, remote_file = parse_s3_url("s3://your-bucket/account.key")
        self.assertEqual(remote_bucket, "your-bucket")
        self.assertEqual(remote_file, "account.key")

        remote_bucket, remote_file = parse_s3_url("s3://my-config-bucket/super-secret-config.json")
        self.assertEqual(remote_bucket, "my-config-bucket")
        self.assertEqual(remote_file, "super-secret-config.json")

        remote_bucket, remote_file = parse_s3_url("s3://your-secure-bucket/account.key")
        self.assertEqual(remote_bucket, "your-secure-bucket")
        self.assertEqual(remote_file, "account.key")

        remote_bucket, remote_file = parse_s3_url("s3://your-bucket/subfolder/account.key")
        self.assertEqual(remote_bucket, "your-bucket")
        self.assertEqual(remote_file, "subfolder/account.key")

        # Sad path
        remote_bucket, remote_file = parse_s3_url("/dev/null")
        self.assertEqual(remote_bucket, "")

    def test_validate_name(self):
        fname = "tests/name_scenarios.json"
        with open(fname, "r") as f:
            scenarios = json.load(f)
        for scenario in scenarios:
            value = scenario["value"]
            is_valid = scenario["is_valid"]
            if is_valid:
                assert validate_name(value)
            else:
                with self.assertRaises(InvalidAwsLambdaName) as exc:
                    validate_name(value)

    def test_contains_python_files_or_subdirs(self):
        self.assertTrue(contains_python_files_or_subdirs("tests/data"))
        self.assertTrue(contains_python_files_or_subdirs("tests/data/test2"))
        self.assertFalse(contains_python_files_or_subdirs("tests/data/test1"))

    def test_conflicts_with_a_neighbouring_module(self):
        self.assertTrue(conflicts_with_a_neighbouring_module("tests/data/test1"))
        self.assertFalse(conflicts_with_a_neighbouring_module("tests/data/test2"))

    def test_titlecase_keys(self):
        raw = {
            "hOSt": "github.com",
            "ConnECtiOn": "keep-alive",
            "UpGRAde-InSecuRE-ReQueSts": "1",
            "uSer-AGEnT": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "cONtENt-TYPe": "text/html; charset=utf-8",
            "aCCEpT": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "ACcePT-encoDInG": "gzip, deflate, br",
            "AcCEpT-lAnGUagE": "en-US,en;q=0.9",
        }
        transformed = titlecase_keys(raw)
        expected = {
            "Host": "github.com",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36",
            "Content-Type": "text/html; charset=utf-8",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
        }
        self.assertEqual(expected, transformed)

    def test_is_valid_bucket_name(self):
        # Bucket names must be at least 3 and no more than 63 characters long.
        self.assertFalse(is_valid_bucket_name("ab"))
        self.assertFalse(is_valid_bucket_name("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefhijlmn"))
        # Bucket names must not contain uppercase characters or underscores.
        self.assertFalse(is_valid_bucket_name("aaaBaaa"))
        self.assertFalse(is_valid_bucket_name("aaa_aaa"))
        # Bucket names must start with a lowercase letter or number.
        self.assertFalse(is_valid_bucket_name(".abbbaba"))
        self.assertFalse(is_valid_bucket_name("abbaba."))
        self.assertFalse(is_valid_bucket_name("-abbaba"))
        self.assertFalse(is_valid_bucket_name("ababab-"))
        # Bucket names must be a series of one or more labels. Adjacent labels are separated by a single period (.).
        # Each label must start and end with a lowercase letter or a number.
        self.assertFalse(is_valid_bucket_name("aaa..bbbb"))
        self.assertFalse(is_valid_bucket_name("aaa.-bbb.ccc"))
        self.assertFalse(is_valid_bucket_name("aaa-.bbb.ccc"))
        # Bucket names must not be formatted as an IP address (for example, 192.168.5.4).
        self.assertFalse(is_valid_bucket_name("192.168.5.4"))
        self.assertFalse(is_valid_bucket_name("127.0.0.1"))
        self.assertFalse(is_valid_bucket_name("255.255.255.255"))

        self.assertTrue(is_valid_bucket_name("valid-formed-s3-bucket-name"))
        self.assertTrue(is_valid_bucket_name("worst.bucket.ever"))


class ApacheNCSAFormatterTestCase(unittest.TestCase):
    def setUp(self):
        self.method = "GET"
        self.datetime_regex = re.compile(
            r"\d+\/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}:\d{2}:\d{2}:\d{2}\s\+\d{4}"
        )
        self.agent = "myagent"

    def _build_expected_format_string(self, status_code, addtional_environ, content_length, **kwargs) -> Tuple[dict, str]:
        referer = "me"
        logname = "-"
        user = "-"
        host = "127.0.0.1"
        server_protocol = "myprot"
        environ = {
            "REMOTE_ADDR": host,
            "HTTP_USER_AGENT": self.agent,
            "HTTP_REFERER": referer,
            "SERVER_PROTOCOL": server_protocol,
            "PATH_INFO": "/my/path/",
            "REQUEST_METHOD": self.method,
        }
        environ.update(addtional_environ)
        query_string = ""
        raw_query_string = environ.get("QUERY_STRING", None)
        if raw_query_string:
            query_string = f"?{raw_query_string}"
        request = f"{self.method} {environ['PATH_INFO']}{query_string} {server_protocol}"

        regex_log_entry = f'{host} {logname} {user} [] "{request}" {status_code} {content_length} "{referer}" "{self.agent}"'
        rt_us = kwargs.get("rt_us")
        if rt_us:
            rt_seconds = int(rt_us / 1_000_000)
            regex_log_entry = f"{regex_log_entry} {rt_seconds}/{rt_us}"
        return environ, regex_log_entry

    def test_with_response_time__true(self):
        formatter = ApacheNCSAFormatter(with_response_time=True)
        expected = "format_log_with_response_time"
        actual = formatter.__name__
        self.assertEqual(actual, expected)

        status_code = 200
        content_length = 10
        rt_us = 15
        environ, expected = self._build_expected_format_string(status_code, {}, content_length, rt_us=15)
        actual = formatter(status_code, environ, content_length, rt_us=rt_us)
        self.assertRegex(actual, self.datetime_regex)
        # extract and remove matched datetime
        result = self.datetime_regex.search(actual)
        match_start, match_end = result.span()
        replace_text = actual[match_start:match_end]
        actual = actual.replace(replace_text, "")
        self.assertEqual(actual, expected)

        agent_endstring = f'"{self.agent}"'
        self.assertFalse(actual.endswith(agent_endstring))

    def test_with_response_time__true__with_querystring(self):
        formatter = ApacheNCSAFormatter(with_response_time=True)

        status_code = 200
        content_length = 10
        rt_us = 15
        additional_environ = {"QUERY_STRING": "name=hello&data=hello"}
        environ, expected = self._build_expected_format_string(status_code, additional_environ, content_length, rt_us=15)
        actual = formatter(status_code, environ, content_length, rt_us=rt_us)
        self.assertRegex(actual, self.datetime_regex)
        # extract and remove matched datetime
        result = self.datetime_regex.search(actual)
        match_start, match_end = result.span()
        replace_text = actual[match_start:match_end]
        actual = actual.replace(replace_text, "")
        self.assertEqual(actual, expected)
        agent_endstring = f'"{self.agent}"'
        self.assertFalse(actual.endswith(agent_endstring))

    def test_with_response_time__false(self):
        formatter = ApacheNCSAFormatter(with_response_time=False)

        expected = "format_log"
        actual = formatter.__name__
        self.assertEqual(actual, expected)

        status_code = 200
        content_length = 10
        environ, expected = self._build_expected_format_string(status_code, {}, content_length)
        actual = formatter(status_code, environ, content_length)
        self.assertRegex(actual, self.datetime_regex)
        # extract and remove matched datetime
        result = self.datetime_regex.search(actual)
        match_start, match_end = result.span()
        replace_text = actual[match_start:match_end]
        actual = actual.replace(replace_text, "")
        self.assertEqual(actual, expected)

        agent_endstring = f'"{self.agent}"'
        self.assertTrue(actual.endswith(agent_endstring))

    def test_with_response_time__false__with_querystring(self):
        formatter = ApacheNCSAFormatter(with_response_time=False)

        status_code = 200
        content_length = 10
        additional_environ = {"QUERY_STRING": "name=hello&data=hello"}
        environ, expected = self._build_expected_format_string(status_code, additional_environ, content_length)
        actual = formatter(status_code, environ, content_length)
        self.assertRegex(actual, self.datetime_regex)
        # extract and remove matched datetime
        result = self.datetime_regex.search(actual)
        match_start, match_end = result.span()
        replace_text = actual[match_start:match_end]
        actual = actual.replace(replace_text, "")
        self.assertEqual(actual, expected)
        agent_endstring = f'"{self.agent}"'
        self.assertTrue(actual.endswith(agent_endstring))
