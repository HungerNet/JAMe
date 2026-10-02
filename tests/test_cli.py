'''Integration tests for the JAMe command-line interface.'''

import json
import sys

from jame.cli.jame_cli import main


def run_cli(monkeypatch, capsys, *arguments: str) -> str:
    monkeypatch.setattr(sys, 'argv', ['jame', *arguments])
    main()
    return capsys.readouterr().out


def test_cli_uses_numbered_wildcard_for_exact_length(monkeypatch, capsys):
    '''Treat numbered wildcard length as exact and unnumbered stars as open-ended.'''
    unbounded = run_cli(
        monkeypatch,
        capsys,
        'tests/files/challenge.txt',
        '--format',
        'hcr{*****}',
    )
    assert 'hcr{abcd}' in unbounded

    exact = run_cli(
        monkeypatch,
        capsys,
        'tests/files/challenge.txt',
        '--format',
        'hcr{*5}',
    )
    assert 'No flag extracted.' in exact
    assert 'hcr{abcd}' not in exact


def test_cli_verbose_prints_structured_analyzer_details(monkeypatch, capsys):
    '''Expose structured result details with the verbose flag.'''
    output = run_cli(
        monkeypatch,
        capsys,
        'crypto',
        'tests/files/strings.txt',
        '--verbose',
    )

    result = json.loads(output)
    assert result['file_path'] == 'tests/files/strings.txt'
    assert 'findings' in result


def test_cli_supports_caesar_method(monkeypatch, capsys):
    '''Expose the Caesar decoder as a CLI command.'''
    output = run_cli(monkeypatch, capsys, 'caesar', 'Khoor', '--shift', '3')

    result = json.loads(output)
    assert result == {'shift': 3, 'decoded': 'Hello'}