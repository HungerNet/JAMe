'''Cryptographic triage helpers for JAMe.'''

import base64
import binascii
import re

from jame.core.utils import entropy_score

_COMMON_ENGLISH_WORDS = frozenset({
    'about', 'after', 'again', 'all', 'also', 'an', 'and', 'any', 'are', 'as', 'at', 'back',
    'be', 'because', 'been', 'before', 'being', 'between', 'both', 'but', 'by', 'can', 'come',
    'could', 'day', 'did', 'do', 'down', 'each', 'even', 'every', 'few', 'first', 'for', 'from',
    'get', 'give', 'go', 'good', 'great', 'had', 'has', 'have', 'he', 'her', 'here', 'him',
    'his', 'how', 'i', 'if', 'in', 'into', 'is', 'it', 'its', 'just', 'know', 'like', 'little',
    'long', 'look', 'make', 'man', 'many', 'may', 'me', 'more', 'most', 'much', 'must', 'my',
    'new', 'no', 'not', 'now', 'of', 'off', 'old', 'on', 'once', 'one', 'only', 'or', 'other',
    'our', 'out', 'over', 'people', 'said', 'same', 'see', 'she', 'should', 'so', 'some',
    'still', 'such', 'take', 'than', 'that', 'the', 'their', 'them', 'then', 'there', 'these',
    'they', 'think', 'this', 'those', 'through', 'time', 'to', 'too', 'two', 'under', 'up', 'us',
    'use', 'very', 'want', 'was', 'way', 'we', 'well', 'were', 'what', 'when', 'where', 'which',
    'while', 'who', 'why', 'will', 'with', 'work', 'would', 'year', 'you', 'your', 'hello',
})


def detect_encoding(value: str | bytes) -> dict:
    '''Detect likely base64/base32/base58 or plain text encodings.'''
    text = value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else value
    candidates = {}
    variants = [
        ('base64', lambda s: base64.b64decode(s + '=' * ((4 - len(s) % 4) % 4), validate=False)),
        ('base32', lambda s: base64.b32decode(s + '=' * ((8 - len(s) % 8) % 8), casefold=True)),
    ]

    cleaned = re.sub(r'[^A-Za-z0-9+/=]', '', text)
    if len(cleaned) >= 8:
        for label, fn in variants:
            try:
                decoded = fn(cleaned)
                candidates[label] = {
                    'decoded': decoded[:80],
                    'confidence': 0.8 if b'\x00' not in decoded else 0.5,
                }
            except (binascii.Error, ValueError):
                continue

    if re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]+', text):
        candidates['base58'] = {'decoded': text[:16], 'confidence': 0.7}

    return {'encoding': candidates, 'input_length': len(text), 'entropy': entropy_score(text.encode('utf-8', errors='ignore'))}


def xor_bruteforce(data: bytes) -> list[dict]:
    '''Try all bytewise XOR keys and report printable results.'''
    results: list[dict] = []
    for key in range(256):
        decoded = bytes(byte ^ key for byte in data)
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in decoded)
        score = printable / max(len(decoded), 1)
        if score > 0.7 or key in (0, 13, 32):
            results.append({
                'key': key,
                'score': round(score, 4),
                'text': decoded[:80].decode('latin1', errors='replace'),
            })
    return results


def _caesar_decode(text: str, shift: int) -> str:
    chars = []
    for char in text:
        if 'a' <= char <= 'z':
            chars.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            chars.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
        else:
            chars.append(char)
    return ''.join(chars)


def caesar_detect(text: str) -> dict:
    '''Bruteforce Caesar shifts and score the English-likelihood of each result.'''
    candidates = []
    english_frequency = {
        'a': 8.17,
        'b': 1.49,
        'c': 2.78,
        'd': 4.25,
        'e': 12.70,
        'f': 2.23,
        'g': 2.02,
        'h': 6.09,
        'i': 6.97,
        'j': 0.15,
        'k': 0.77,
        'l': 4.03,
        'm': 2.41,
        'n': 6.75,
        'o': 7.51,
        'p': 1.93,
        'q': 0.10,
        'r': 5.99,
        's': 6.33,
        't': 9.06,
        'u': 2.76,
        'v': 0.98,
        'w': 2.36,
        'x': 0.15,
        'y': 1.97,
        'z': 0.07,
    }
    max_frequency = max(english_frequency.values())

    for shift in range(1, 26):
        decoded = _caesar_decode(text, shift)
        letters = [char for char in decoded.lower() if char in english_frequency]
        score = len(letters)
        average_frequency = sum(english_frequency[char] for char in letters) / max(len(letters), 1)
        words = [word for word in re.findall(r'[a-z]+', decoded.lower()) if len(word) >= 3]
        common_word_ratio = sum(word in _COMMON_ENGLISH_WORDS for word in words) / max(len(words), 1)
        letter_confidence = average_frequency / max_frequency if letters else 0.0
        confidence = (0.85 * common_word_ratio) + (0.15 * letter_confidence)
        candidates.append({
            'shift': shift,
            'decoded': decoded,
            'score': score,
            'confidence': round(confidence, 4),
        })
    ranked_candidates = sorted(candidates, key=lambda item: item['confidence'], reverse=True)
    return {
        'results': ranked_candidates,
        'best': ranked_candidates[0] if ranked_candidates else None,
    }


def vigenere_detect(text: str) -> dict:
    '''Rough Vigenere signature detection by trying short key lengths.'''
    results = []
    for key_len in range(1, 13):
        chunks = [text[index:index + key_len] for index in range(0, len(text), key_len)]
        score = 0
        for chunk in chunks:
            for ch in chunk:
                if ch.isalpha():
                    score += 1
        results.append({'key_length': key_len, 'score': score})
    return {'candidates': sorted(results, key=lambda item: item['score'], reverse=True)[:6]}


def identify_hash(value: str) -> dict:
    '''Identify common hash strings by length and digest structure.'''
    value = value.strip()
    lengths = {
        32: 'md5',
        40: 'sha1',
        56: 'sha224',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512',
    }
    if len(value) in lengths and re.fullmatch(r'[0-9a-fA-F]+', value):
        return {'hash_type': lengths[len(value)], 'confidence': 0.9}
    return {'hash_type': 'unknown', 'confidence': 0.0}


def entropy_score_for_text(value: str | bytes) -> float:
    '''Return Shannon entropy for the supplied bytes or text.'''
    if isinstance(value, str):
        value = value.encode('utf-8', errors='ignore')
    return entropy_score(value)
