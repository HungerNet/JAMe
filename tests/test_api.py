'''Integration tests for JAMe's public API.'''

import shutil
from pathlib import Path

import jame
from jame import Jame

FILES = Path(__file__).parent / 'files'


def test_file_type_and_strings_read_real_file():
    '''Identify a text file and extract its printable content.'''
    sample = FILES / 'strings.txt'

    engine = Jame()
    file_type = engine.getFileType(str(sample))
    strings = engine.runStrings(str(sample))

    print(f'getFileType: {file_type}')
    print(f'runStrings: {strings}')

    assert file_type == 'text file'
    assert 'Visible message for strings testing.' in strings


def test_find_flag_matches_fixed_wildcard_count():
    '''Find a flag whose payload has the requested fixed character count.'''
    sample = FILES / 'challenge.txt'

    flag = Jame().findFlag(str(sample), 'hcr{*4}')
    print(f'findFlag fixed count: {flag}')

    assert flag == 'hcr{abcd}'


def test_find_flag_matches_escaped_literal_suffix():
    '''Match wildcard payloads followed by an escaped literal digit.'''
    sample = FILES / 'challenge.txt'

    flag = Jame().findFlag(str(sample), r'flag{*2-******\2}')
    print(f'findFlag escaped suffix: {flag}')

    assert flag == 'flag{ab-abcdef2}'


def test_auto_solve_finds_flag_in_real_file():
    '''Run the high-level solve workflow against a file containing a flag.'''
    sample = FILES / 'solution.txt'

    result = Jame().autoSolve(str(sample), format='flag{*}')
    print(f'autoSolve: {result.summary}; flag={result.flag}')

    assert result.flag == 'flag{real_file_test}'
    assert 'Flag candidate found' in result.summary


def test_scan_file_returns_analysis_results():
    '''Run the combined scan against a real file and inspect its results.'''
    sample = FILES / 'scan.txt'

    result = Jame().scanFile(str(sample))
    print(f'scanFile: type={result.file_type}; confidence={result.confidence}; {result.summary}')

    assert result.file_type == 'text file'
    assert {'crypto', 'binary', 'stego', 'forensics'} <= result.details.keys()
    assert result.raw_output


def test_module_level_scan_file():
    '''Scan a real file through the module-level API.'''
    sample = FILES / 'scan.txt'

    result = jame.scanFile(str(sample))
    print(f'jame.scanFile: type={result.file_type}; confidence={result.confidence}')

    assert result.file_type == 'text file'
    assert result.details


def test_module_level_configuration_persists_across_calls():
    '''Keep module-level configuration for later module-level operations.'''
    sample = FILES / 'config.txt'

    try:
        jame.setFlagPatterns(['ctf{*}'])
        jame.setMaxDepth(7)
        jame.setVerbose(True)

        result = jame.autoSolve(str(sample))
        print(
            'module configuration: '
            f'flag_patterns={jame._engine.flag_patterns}; '
            f'max_depth={result.details["max_depth"]}; '
            f'verbose={result.details["verbose"]}; flag={result.flag}'
        )

        assert result.flag == 'ctf{shared_engine}'
        assert result.details['max_depth'] == 7
        assert result.details['verbose'] is True
    finally:
        jame.setFlagPatterns(['flag{*}', 'hcr{*}', 'CTFx{*}'])
        jame.setMaxDepth(3)
        jame.setVerbose(False)


def test_category_analyzers_accept_real_file():
    '''Exercise category analyzers through their user-facing methods.'''
    sample = FILES / 'strings.txt'
    engine = Jame()
    crypto = engine.cryptoAnalyze(str(sample))
    binary = engine.binaryAnalyze(str(sample))
    stego = engine.stegoAnalyze(str(sample))
    forensics = engine.forensicsAnalyze(str(sample))

    print(f'cryptoAnalyze: {crypto.summary} (confidence={crypto.confidence})')
    print(f'binaryAnalyze: {binary.summary} (confidence={binary.confidence})')
    print(f'stegoAnalyze: {stego.summary} (confidence={stego.confidence})')
    print(f'forensicsAnalyze: {forensics.summary} (confidence={forensics.confidence})')

    assert crypto.file_path == str(sample)
    assert binary.file_path == str(sample)
    assert stego.file_path == str(sample)
    assert forensics.file_path == str(sample)


def test_archive_extract_extracts_real_zip_file(tmp_path):
    '''Extract an actual ZIP archive through the public archive method.'''
    archive_path = tmp_path / 'sample.zip'
    shutil.copyfile(FILES / 'sample.zip', archive_path)

    extracted = Jame().archiveExtract(str(archive_path))
    print(f'archiveExtract: {extracted}')

    assert len(extracted) == 1
    assert (tmp_path / '.jame_extract' / 'payload.txt').read_text(encoding='utf-8') == 'archive payload'


def test_decode_caesar_with_explicit_shift():
    '''Decode a known Caesar ciphertext using the public method.'''
    result = Jame().decodeCaesar('Khoor', 3)
    print(f'decodeCaesar: {result}')

    assert result == {'shift': 3, 'decoded': 'Hello'}


def test_decode_caesar_bruteforce():
    '''Find the known Caesar plaintext among brute-force shift candidates.'''
    result = Jame().decodeCaesar('Khoor', 'brute')
    print(f'decodeCaesar brute force: {result}')

    candidates = result['results']
    assert len(candidates) == 25
    assert {candidate['shift'] for candidate in candidates} == set(range(1, 26))
    assert all(0.0 <= candidate['confidence'] <= 1.0 for candidate in candidates)
    assert any(candidate['shift'] == 3 and candidate['decoded'] == 'Hello' for candidate in candidates)
    assert result['best']['shift'] == 3


def test_decode_caesar_bruteforce_long_english_sentences():
    '''Crack file-based ciphertexts for coherent and semantically odd sentences.'''
    ciphertexts = (FILES / 'caesar_ciphertexts.txt').read_text(encoding='utf-8').splitlines()
    sentences = (FILES / 'caesar_plaintexts.txt').read_text(encoding='utf-8').splitlines()
    shifts = [1, 7, 13]

    assert len(ciphertexts) == len(sentences) == len(shifts) == 3

    for ciphertext, sentence, expected_shift in zip(ciphertexts, sentences, shifts):
        result = Jame().decodeCaesar(ciphertext, 'brute')
        print(f'file ciphertext: {ciphertext}')
        print(f'brute-force result: {result["best"]}')

        assert result['best']['shift'] == expected_shift
        assert result['best']['decoded'] == sentence


def test_configuration_methods_update_instance():
    '''Apply the public configuration methods and verify their values.'''
    engine = Jame()
    engine.setFlagPatterns(['ctf{*}'])
    engine.setMaxDepth(5)
    engine.setVerbose(True)
    print(
        'instance configuration: '
        f'flag_patterns={engine.flag_patterns}; '
        f'max_depth={engine.max_depth}; verbose={engine.verbose}'
    )

    assert engine.flag_patterns == ['ctf{*}']
    assert engine.max_depth == 5
    assert engine.verbose is True


def test_run_binwalk_returns_structured_result_for_file():
    '''Return a structured binwalk result even when the tool is unavailable.'''
    sample = FILES / 'binary_sample.bin'

    result = Jame().runBinwalk(str(sample))
    print(
        f'runBinwalk: available={result.available}; '
        f'summary={result.summary}; matches={result.matches}'
    )

    assert result.file_path == str(sample)
    assert isinstance(result.available, bool)
    assert result.summary
