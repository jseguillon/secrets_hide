import unittest

# Redaction function
import re

# Updated Redaction function with regex support
def redact_secrets(log, redacted_list):
    redacted_lines = []

    for line in log.splitlines():
        for item in redacted_list:
            search_term = item['search']
            prefix_len = item['prefix']
            suffix_len = item['suffix']

            if re.search(search_term, line):
                # Find all matches including position for the term
                matches = list(re.finditer(search_term, line))
                for match in matches:
                    # For each match, process the following word to redact
                    start, end = match.span()
                    end_space = line.find(' ', end) if ' ' in line[end:] else len(line)
                    secret_part = line[end:end_space]  # Extract the word after the search term
                    secret_len = len(secret_part)
                    if secret_len > (prefix_len + suffix_len):
                        redacted_secret = secret_part[:prefix_len] + "XXXXXXXX" + secret_part[-suffix_len:]
                    else:
                        # If the secret is shorter than prefix+suffix, redact middle part
                        redacted_secret = secret_part[:prefix_len] + "XXXXXXXX" + secret_part[prefix_len:]

                    # Replace the secret in the line
                    line = line[:end] + line[end:].replace(secret_part, redacted_secret, 1)

        print(line)
        redacted_lines.append(line)  # Append the (possibly modified) line

    return "\n".join(redacted_lines)

# Unit tests
class TestRedactSecrets(unittest.TestCase):

    def setUp(self):
        # Configuration for secrets to redact with prefix and suffix lengths
        self.redacted_list = [
            {'search': 'my_secret:', 'prefix': 4, 'suffix': 3},
            {'search': 'my_other_secret=', 'prefix': 5, 'suffix': 6}
        ]

    def test_redact_basic_case(self):
        log_input = """
        - the secret we set is my_secret: ASECRETVALUE
        + the secret we set is my_secret: NEWVALUE
        """
        expected_output = """
        - the secret we set is my_secret: ASECXXXXXXXXLUE
        + the secret we set is my_secret: NEWVXXXXXXXXLUE
        """
        result = redact_secrets(log_input.strip(), self.redacted_list)
        self.assertEqual(result.strip(), expected_output.strip())

    def test_redact_multiple_values(self):
        log_input = """
        - the secret we set is my_other_secret=ASECRETVALUE and also set non_secret_value: BEFOREVALUE
        + the secret we set is my_other_secret=MYNEWVALUE and also set non_secret_value: AFTERVALUE
        """
        expected_output = """
        - the secret we set is my_other_secret=ASECRXXXXXXXXTVALUE and also set non_secret_value: BEFOREVALUE
        + the secret we set is my_other_secret=MYNEWXXXXXXXXVALUE and also set non_secret_value: AFTERVALUE
        """
        result = redact_secrets(log_input.strip(), self.redacted_list)
        self.assertEqual(result.strip(), expected_output.strip())

    def test_redact_with_short_value(self):
        log_input = """
        - the secret we set is my_other_secret=MYNEWVALUE
        """
        expected_output = """
        - the secret we set is my_other_secret=MYXXXXXXXUE
        """
        result = redact_secrets(log_input.strip(), self.redacted_list)
        self.assertEqual(result.strip(), expected_output.strip())

    def test_no_secret_to_redact(self):
        log_input = """
        - the secret we set is no_secret: KEEPTHIS
        """
        expected_output = """
        - the secret we set is no_secret: KEEPTHIS
        """
        result = redact_secrets(log_input.strip(), self.redacted_list)
        self.assertEqual(result.strip(), expected_output.strip())

# Running the unit tests
unittest.main(argv=[''], exit=False)