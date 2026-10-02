'''Pattern matching helpers for JAMe.'''

import re


def _parse_pattern(pattern: str) -> list[str | tuple[str, int]]:
    '''Convert a wildcard pattern into a simple token stream.'''
    tokens: list[str | tuple[str, int]] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == '*':
            end = index + 1
            while end < len(pattern) and pattern[end].isdigit():
                end += 1
            if end > index + 1:
                amount = int(pattern[index + 1:end])
            else:
                amount = 0
            tokens.append(('*', amount))
            index = end
            continue
        if char == '\\' and index + 1 < len(pattern):
            tokens.append(pattern[index + 1])
            index += 2
            continue
        tokens.append(char)
        index += 1
    return tokens


def match_pattern(text: str, pattern: str) -> bool:
    '''Match text against a wildcard pattern using a custom matcher.

    Supported patterns are literal text with '*' placeholders such as:
    - hcr{*4}
    - flag{*2-******\2}
    - flag{*}
    '''
    if pattern == '':
        return text == ''

    tokens = _parse_pattern(pattern)

    def _match(text_index: int, token_index: int) -> bool:
        if token_index == len(tokens):
            return text_index == len(text)

        token = tokens[token_index]
        if isinstance(token, tuple):
            _, amount = token
            if amount == 0:
                for span in range(len(text) - text_index + 1):
                    if _match(text_index + span, token_index + 1):
                        return True
                return False
            if text_index + amount > len(text):
                return False
            return _match(text_index + amount, token_index + 1)

        literal = str(token)
        if text.startswith(literal, text_index):
            return _match(text_index + len(literal), token_index + 1)
        return False

    return _match(0, 0)


def find_pattern_tokens(text: str) -> list[str]:
    '''Extract braces-wrapped strings likely to contain flag-like values.'''
    matches = re.findall(r'[A-Za-z0-9_]{2,}\{[^\n\r}]{1,120}\}', text)
    return matches
