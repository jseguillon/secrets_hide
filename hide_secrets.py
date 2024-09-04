import sys

def redact_secrets_line_by_line(prefixes):
    for line in sys.stdin:
        # Process each line as it's received
        redacted = False
        # Look for any of the prefixes in the line
        for prefix in prefixes:
            if prefix in line:
                # Split the line at the prefix and redact the secret part after ":"
                key_part, value_part = line.split(prefix + ": ", 1)
                if len(value_part) > 8:
                    redacted_value = value_part[:4] + "XXXXXXXX" + value_part[-4:]
                else:
                    redacted_value = value_part  # In case the value is too short to redact
                sys.stdout.write(f"{key_part}{prefix}: {redacted_value}\n")
                redacted = True
                break
        
        # If no prefix is found, output the line unchanged
        if not redacted:
            sys.stdout.write(line)

if __name__ == "__main__":
    # List of prefixes to filter
    prefixes_to_redact = ["my_secret", "another_secret"]

    # Process input line by line and stream output
    redact_secrets_line_by_line(prefixes_to_redact)
