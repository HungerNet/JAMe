'''Command-line entry point for JAMe.'''

import json
import os
import subprocess
import sys

from c2e import LiveCLI, command
from mapres import ascii_colors, rprint, res, setGlobalMaps

from jame import Jame

setGlobalMaps(ascii_colors)
_COLOR_ENABLED = sys.stdout.isatty() and 'NO_COLOR' not in os.environ


def _paint(text: object, color: str, *, bold: bool = False) -> str:
    if not _COLOR_ENABLED:
        return str(text)
    style = res(f'<{color}>')
    if bold:
        style = res('<bold>') + style
    return f'{style}{text}{res("<reset>")}'


def _print_result(cli: LiveCLI, result: object, detailed: bool = False) -> None:
    if detailed:
        to_dict = getattr(result, 'to_dict', None)
        output = to_dict() if callable(to_dict) else result
        cli.safePrint(json.dumps(output, indent=2, default=str))
    elif hasattr(result, 'summary'):
        if hasattr(result, 'flag'):
            color = 'green' if result.flag else 'yellow'
        else:
            color = 'green' if getattr(result, 'confidence', 0.0) >= 0.7 else 'aqua'
        cli.safePrint(_paint(result.summary, color))
        if getattr(result, 'flag', None):
            cli.safePrint(_paint(result.flag, 'green', bold=True))
    elif result is None:
        cli.safePrint(_paint('No flag found.', 'yellow'))
    elif isinstance(result, list):
        output = '\n'.join(str(item) for item in result) if result else 'No results.'
        cli.safePrint(_paint(output, 'blue'))
    elif isinstance(result, (dict, tuple)):
        cli.safePrint(_paint(json.dumps(result, indent=2, default=str), 'blue'))
    else:
        cli.safePrint(_paint(result, 'aqua'))


@command('solve')
def solve(cli: LiveCLI, path: str) -> None:
    '''Find a flag and extract supported archives.'''
    engine = Jame(flag_patterns=[format()], max_depth=max_depth(), verbose=verbose())
    result = engine.autoSolve(
        path,
        format=format(),
        maxDepth=max_depth(),
        verbose=verbose(),
    )
    _print_result(cli, result, verbose())


@solve.param('format', type=str, default='flag{*}')
def _solve_format(value):
    '''Flag pattern; '*' matches any length and '*N' matches exactly N characters.'''
    return value


@solve.param('max-depth', type=int, default=3)
def _solve_max_depth(value):
    '''Maximum recursive archive extraction depth.'''
    return value


@solve.flag('verbose')
def _solve_verbose(value):
    '''Print structured result details.'''
    return value


@command('find-flag')
def find_flag(cli: LiveCLI, path: str) -> None:
    '''Find a flag matching a wildcard pattern.'''
    result = Jame().findFlag(path, format())
    _print_result(cli, result, verbose())


@find_flag.param('format', type=str, default='flag{*}')
def _find_flag_format(value):
    '''Flag pattern; '*' matches any length and '*N' matches exactly N characters.'''
    return value


@find_flag.flag('verbose')
def _find_flag_verbose(value):
    '''Print structured result details.'''
    return value


def _register_path_command(name: str, method_name: str, description: str) -> None:
    @command(name)
    def handler(cli: LiveCLI, path: str) -> None:
        result = getattr(Jame(), method_name)(path)
        _print_result(cli, result, verbose())

    handler.func.__doc__ = description
    handler.desc = description
    def verbose_flag(value):
        '''Print structured result details.'''
        return value

    handler.flag('verbose')(verbose_flag)


_register_path_command('scan', 'scanFile', 'Run all available analyzers.')
_register_path_command('crypto', 'cryptoAnalyze', 'Analyze crypto indicators.')
_register_path_command('binary', 'binaryAnalyze', 'Analyze binary indicators.')
_register_path_command('stego', 'stegoAnalyze', 'Check for steganography indicators.')
_register_path_command('forensics', 'forensicsAnalyze', 'Run forensic checks.')
_register_path_command('file-type', 'getFileType', 'Detect the file type.')
_register_path_command('strings', 'runStrings', 'Extract printable strings.')
_register_path_command('binwalk', 'runBinwalk', 'Run binwalk when installed.')


@command('archive')
def archive(cli: LiveCLI, path: str) -> None:
    '''Extract supported archives.'''
    engine = Jame(max_depth=max_depth(), verbose=verbose())
    _print_result(cli, engine.archiveExtract(path), verbose())


@archive.param('max-depth', type=int, default=3)
def _archive_max_depth(value):
    '''Maximum recursive archive extraction depth.'''
    return value


@archive.flag('verbose')
def _archive_verbose(value):
    '''Print structured result details.'''
    return value


@command('caesar')
def caesar(cli: LiveCLI, text: str) -> None:
    '''Decode Caesar-shifted text.'''
    shift_value = shift()
    if shift_value != 'brute':
        try:
            shift_value = int(shift_value)
        except ValueError:
            cli.safePrint("Error: --shift must be an integer or 'brute'")
            raise SystemExit(2) from None
    result = Jame().decodeCaesar(text, shift_value)
    if verbose():
        _print_result(cli, result, detailed=True)
    elif shift_value == 'brute':
        best = result.get('best')
        if best:
            cli.safePrint(_paint(best['decoded'], 'green', bold=True))
        else:
            cli.safePrint(_paint('No Caesar candidate found.', 'yellow'))
    else:
        cli.safePrint(_paint(result.get('decoded', result.get('error', '')), 'green'))


@caesar.param('shift', type=str, default='brute')
def _caesar_shift(value):
    '''Integer shift or 'brute' to check every Caesar shift.'''
    return value


@caesar.flag('verbose')
def _caesar_verbose(value):
    '''Print structured result details.'''
    return value


@command('update')
def update(cli: LiveCLI) -> None:
    '''Upgrade JAMe and C2E, optionally including the MapRes prerelease.'''
    rprint(_paint('Updating JAMe...', 'aqua'))
    command = [sys.executable, '-m', 'pip', 'install', '--upgrade']
    if pre():
        command.append('--pre')
    command.extend(['c2e', 'jame'])
    if pre():
        command.append('mapres')
    result = subprocess.run(command, check=False)
    if result.returncode:
        raise SystemExit(result.returncode)


@update.flag('pre')
def _update_pre(value):
    '''Include pre-release versions when upgrading.'''
    return value


def main() -> None:
    '''Parse command-line options and dispatch them through C2E.'''
    LiveCLI().run_argv(
        prog='jame',
        description='Just Another Method of Exploitation',
        default_command='solve',
    )


if __name__ == '__main__':
    main()