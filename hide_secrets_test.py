from hide_secrets import redact_secrets

import pytest

@pytest.fixture
def redacted_config():
    # Configuration for secrets to redact with prefix and suffix lengths
    return [
        {'search': r'my_secret: (\w+)', 'prefix': 4, 'suffix': 3},
        {'search': r'my_other_secret=(\w+)', 'suffix': 2},
        {'search': r'my_fail_secret=(\w+)', 'prefix': 8, 'suffix': 2},
        {'search': r'Password=(\w+)', 'size': 3}
    ]

def test_redact_mssql(redacted_config):
    log_input = """
    value: Data Source=xxx;Password=MYPASS12;Connection
    """
    expected_output = """
    value: Data Source=xxx;Password=MXXX2;Connection
    """
    result = redact_secrets(log_input.strip(), redacted_config)
    assert result.strip() == expected_output.strip()

def test_redact_basic_case(redacted_config):
    log_input = """
    - the secret we set is my_secret: ASECRETVALUE
    + the secret we set is my_secret: NEWVALUE
    """
    expected_output = """
    - the secret we set is my_secret: ASECXXXXXLUE
    + the secret we set is my_secret: NEWVXLUE
    """
    result = redact_secrets(log_input.strip(), redacted_config)
    assert result.strip() == expected_output.strip()

def test_redact_multiple_values(redacted_config):
    log_input = """
    - the secret we set is my_other_secret=ASECRETVALUE and also set non_secret_value: BEFOREVALUE
    + the secret we set is my_other_secret=MYNEWVALUE and also set non_secret_value: AFTERVALUE
    """
    expected_output = """
    - the secret we set is my_other_secret=AXXXXXXXXXUE and also set non_secret_value: BEFOREVALUE
    + the secret we set is my_other_secret=MXXXXXXXUE and also set non_secret_value: AFTERVALUE
    """
    '\n    + the secret we set is my_other_secret=MXXXXXXXUE and also set non_secret_value: AFTERVALUE'
    result = redact_secrets(log_input.strip(), redacted_config)
    assert result.strip() == expected_output.strip()

def test_redact_with_short_value(redacted_config):
    log_input = """
    - the secret we set is my_other_secret=MYNEWVALUE
    """
    expected_output = """
    - the secret we set is my_other_secret=MXXXXXXXUE
    """
    result = redact_secrets(log_input.strip(), redacted_config)
    assert result.strip() == expected_output.strip()

def test_no_secret_to_redact(redacted_config):
    log_input = """
    - the secret we set is no_secret: KEEPTHIS
    """
    expected_output = """
    - the secret we set is no_secret: KEEPTHIS
    """
    result = redact_secrets(log_input.strip(), redacted_config)
    assert result.strip() == expected_output.strip()
