'''Command-line entry point for JAMe.'''

import argparse
import json
import sys

from jame import Jame


_COMMANDS = {
    'archive',
    'binary',
    'binwalk',
    'caesar',
    'crypto',
    'file-type',
    'find-flag',
    'forensics',
    'scan',
    'solve',
    'stego',
    'strings',
}


def _add_path_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument('path', help='Path to the file to analyze')
    command.add_argument('--verbose', action='store_true', help='Print structured result details')


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='jame',
        description='Just Another Method of Exploitation',
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    solve = subparsers.add_parser('solve', help='Find a flag and extract supported archives')
    _add_path_arguments(solve)
    solve.add_argument(
        '--format',
        default='flag{*}',
        help="Flag pattern; '*' matches any length and '*N' matches exactly N characters",
    )
    solve.add_argument('--max-depth', type=int, default=3, help='Archive extraction depth')

    find_flag = subparsers.add_parser('find-flag', help='Find a flag matching a pattern')
    _add_path_arguments(find_flag)
    find_flag.add_argument(
        '--format',
        default='flag{*}',
        help="Flag pattern; '*' matches any length and '*N' matches exactly N characters",
    )

    for name, description in (
        ('scan', 'Run all available analyzers'),
        ('crypto', 'Analyze crypto indicators'),
        ('binary', 'Analyze binary indicators'),
        ('stego', 'Check for steganography indicators'),
        ('forensics', 'Run forensic checks'),
        ('file-type', 'Detect the file type'),
        ('strings', 'Extract printable strings'),
        ('binwalk', 'Run binwalk when installed'),
    ):
        command = subparsers.add_parser(name, help=description)
        _add_path_arguments(command)

    archive = subparsers.add_parser('archive', help='Extract supported archives')
    _add_path_arguments(archive)
    archive.add_argument('--max-depth', type=int, default=3, help='Archive extraction depth')

    caesar = subparsers.add_parser('caesar', help='Decode Caesar-shifted text')
    caesar.add_argument('text', help='Text to decode')
    caesar.add_argument('--shift', default='brute', help="Integer shift or 'brute'")
    caesar.add_argument('--verbose', action='store_true', help='Print structured result details')

    return parser


def _print_result(result: object, verbose: bool) -> None:
    if verbose:
        to_dict = getattr(result, 'to_dict', None)
        output = to_dict() if callable(to_dict) else result
        print(json.dumps(output, indent=2, default=str))
    elif hasattr(result, 'summary'):
        print(result.summary)
    elif result is None:
        print('No flag found.')
    elif isinstance(result, list):
        print('\n'.join(str(item) for item in result) if result else 'No results.')
    elif isinstance(result, (dict, tuple)):
        print(json.dumps(result, indent=2, default=str))
    else:
        print(result)


def main() -> None:
    '''Parse command-line options and run the requested JAMe method.'''
    argv = sys.argv[1:]
    if argv and argv[0] not in _COMMANDS and argv[0] not in {'-h', '--help'}:
        argv.insert(0, 'solve')

    parser = _build_parser()
    args = parser.parse_args(argv)
    max_depth = getattr(args, 'max_depth', 3)
    engine = Jame(
        flag_patterns=[getattr(args, 'format', 'flag{*}')],
        max_depth=max_depth,
        verbose=args.verbose,
    )

    if args.command == 'solve':
        result = engine.autoSolve(
            args.path,
            format=args.format,
            maxDepth=args.max_depth,
            verbose=args.verbose,
        )
    elif args.command == 'find-flag':
        result = engine.findFlag(args.path, args.format)
    elif args.command == 'scan':
        result = engine.scanFile(args.path)
    elif args.command == 'crypto':
        result = engine.cryptoAnalyze(args.path)
    elif args.command == 'binary':
        result = engine.binaryAnalyze(args.path)
    elif args.command == 'stego':
        result = engine.stegoAnalyze(args.path)
    elif args.command == 'forensics':
        result = engine.forensicsAnalyze(args.path)
    elif args.command == 'archive':
        engine.setMaxDepth(args.max_depth)
        result = engine.archiveExtract(args.path)
    elif args.command == 'file-type':
        result = engine.getFileType(args.path)
    elif args.command == 'strings':
        result = engine.runStrings(args.path)
    elif args.command == 'binwalk':
        result = engine.runBinwalk(args.path)
    else:
        try:
            shift = 'brute' if args.shift == 'brute' else int(args.shift)
        except ValueError:
            parser.error("--shift must be an integer or 'brute'")
        result = engine.decodeCaesar(args.text, shift)

    _print_result(result, args.verbose)


if __name__ == '__main__':
    main()