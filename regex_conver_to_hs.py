import re

# Prompt the user to enter a regular expression
regex_str = input('Enter a regular expression in single quotes ('): ')
# regex_str = r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}'
# Remove enclosing quotes
regex_str=regex_str.strip('"\'')
# Remove unnecessary backslashes
regex_str=re.sub(r'\\([^\s])', r'\1', regex_str)
# Add any Hyperscan-specific flags, if needed
flags='i'
if re.search(r'\.\*', regex_str):
    flags += 's'
# Print the modified regular expression
print("Here's your converted Regular Expression, to Hyperscan Regex compatible flag:\n" +
      regex_str + ' /' + flags)
