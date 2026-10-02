'''Integration tests for the JAMe command-line interface.'''

import json
import sys
from types import SimpleNamespace

from mapres import ascii_colors

from jame.cli import jame_cli
from jame.cli.jame_cli import main


def run_cli(monkeypatch, capsys, *arguments: str) -> str:
    monkeypatch.setattr(sys, 'argv', ['jame', *arguments])
    monkeypatch.setattr(jame_cli, '_COLOR_ENABLED', False)
    main()
    return capsys.readouterr().out


def test_cli_uses_mapres_color_tokens(monkeypatch):
    '''Render color tokens from MapRes's registered ASCII map.'''
    monkeypatch.setattr(jame_cli, '_COLOR_ENABLED', True)

    assert jame_cli._paint('candidate', 'orange') == f'{ascii_colors.orange}candidate{ascii_colors.reset}'


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
    '''Return only the best Caesar decode by default.'''
    output = run_cli(monkeypatch, capsys, 'caesar', 'Khoor')

    assert output.strip() == 'Hello'


def test_cli_caesar_verbose_shows_ranked_candidates(monkeypatch, capsys):
    '''Expose ranked Caesar candidates through verbose output.'''
    output = run_cli(monkeypatch, capsys, 'caesar', 'Khoor', '--verbose')

    result = json.loads(output)
    assert result['best']['decoded'] == 'Hello'
    assert len(result['results']) == 25


def test_cli_caesar_explicit_shift(monkeypatch, capsys):
    '''Decode one Caesar shift without verbose metadata.'''
    output = run_cli(monkeypatch, capsys, 'caesar', 'Khoor', '--shift', '3')

    assert output.strip() == 'Hello'


def test_cli_update_pre_requests_prereleases(monkeypatch, capsys):
    '''Pass --pre through to pip when updating JAMe and C2E.'''
    calls = []

    def fake_run(arguments, check):
        calls.append((arguments, check))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(jame_cli.subprocess, 'run', fake_run)
    run_cli(monkeypatch, capsys, 'update', '--pre')

    arguments, check = calls[0]
    assert arguments[-5:] == ['--upgrade', '--pre', 'c2e', 'jame', 'mapres']
    assert check is False


def test_cli_stable_update_leaves_mapres_prerelease_installed(monkeypatch, capsys):
    '''Avoid downgrading the required MapRes API during a stable update.'''
    calls = []

    def fake_run(arguments, check):
        calls.append(arguments)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(jame_cli.subprocess, 'run', fake_run)
    run_cli(monkeypatch, capsys, 'update')

    assert calls[0][-2:] == ['c2e', 'jame']
    assert '--pre' not in calls[0]
    assert 'mapres' not in calls[0]