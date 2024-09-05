#!python3

import sys
import re
def redact_secrets(log, redacted_list):
    redacted_lines = []
    
    for line in log.splitlines():
        for item in redacted_list:
            search_pattern = item['search']
            if 'prefix' in item:
                prefix_len = item['prefix']
            else: 
                prefix_len=1
            if 'suffix' in item:
                suffix_len = item['suffix']
            else: 
                suffix_len = 1
            
            # Use regex to find matches for the search pattern
            regex = re.compile(search_pattern)
            matches = regex.finditer(line)
            
            # Iterate over all matches and replace them
            for match in matches:
                secret_part = match.group(1)
                secret_len = len(secret_part)
                x_length=0
                if "size" in item:
                    x_length=item["size"]
                else: 
                    x_length = secret_len - (prefix_len + suffix_len)
                if secret_len > (prefix_len + suffix_len):
                    redacted_secret = secret_part[:prefix_len] + "X"*x_length + secret_part[-suffix_len:]
                else:
                    # Even if the secret is shorter than prefix+suffix, redact middle part
                    redacted_secret = secret_part[:prefix_len] + "YYY" + secret_part[prefix_len:]
                
                # Replace the secret in the line
                line = line.replace(secret_part, redacted_secret)
        
        redacted_lines.append(line)  # Append the (possibly modified) line
    
    return "\n".join(redacted_lines)

def redacted_config():
    # Configuration for secrets to redact with prefix and suffix lengths
    return [
        {'search': r'my_secret: (\w+)', 'prefix': 4, 'suffix': 3},
        {'search': r'my_other_secret=(\w+)', 'prefix': 1, 'suffix': 2},
        {'search': r'my_fail_secret=(\w+)', 'prefix': 8, 'suffix': 2},
        {'search': r'Password=(\w+)', 'prefix': 1, 'suffix': 1, 'size': 3}
    ]

for line in sys.stdin:
    print(redact_secrets(line,redacted_config()))
