#!/usr/bin/env python

'''>>>>>>>> check_freenas_api - Monitoring plugin for FreeNAS systems <<<<<<<<
This plugin utilizes the REST API and have been tested on FreeNAS 9.3.1'''

developers = ['Joel Rangsmo <joel@rangsmo.se>']
description = __doc__
version = '0.1'
license = 'GPLv2'

try:
    import time
    import logging
    import argparse
    import requests
    import nagiosplugin

except ImportError as missing:
    print(
        'Could not import all required Python modules: "%s".\n' % missing +
        'Installation with PIP: "pip install argparse requests nagiosplugin"')

    exit(3)

_log = logging.getLogger('nagiosplugin')

# ----------------------------------------------------------------------------

class _HelpAction(argparse._HelpAction):
    '''Custom help handler for argparse that includes mode subparsers'''

    def __call__(self, parser, namespace, values, option_string=None):
        parser.print_help()
        
        print('\nSyntax help for check modes:')

        separator = (
            '\n-------------------------------------------'
            '----------------------------------')

        subparsers_actions = [
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)]

        for subparsers_action in subparsers_actions:
            for choice, subparser in subparsers_action.choices.items():
                print(separator)
                print('Check mode "%s"' % format(choice))
                print(subparser.format_help())

        parser.exit(3)


def parse_args(description=None, version=None, developers=None, license=None):
    '''Parses commandline arguments provided by the user'''

    parser = argparse.ArgumentParser(
        description=description,
        add_help=False,
        epilog=(
            'Developed by %s - licensed under %s!'
            % (', '.join(developers), license)))

    # Session options
    parser_session = parser.add_argument_group(title='Session options')

    parser_session.add_argument(
        '-H', '--host',
        help='FreeNAS host address',
        metavar='FN.HOST.ADDRESS', type=str, required=True)

    parser_session.add_argument(
        '-a', '--api-version',
        help='FreeNAS API version (default: %(default)s)',
        choices=['1.0'], default='1.0')

    parser_session.add_argument(
        '-u', '--user',
        help='User for API authentication',
        metavar='username', type=str, required=True)

    parser_session.add_argument(
        '-p', '--password',
        help='Password for API authentication',
        metavar='SecRTG0dd', type=str, required=True)

    parser_session.add_argument(
        '-P', '--port',
        help='Port for HTTPS API communication (default: %(default)i)',
        metavar='PORTNR', type=int, default=443)

    parser_session.add_argument(
        '-i', '--insecure', dest='verify',
        help='Disable certificate verification (not recommended)',
        action='store_false', default=True)
    
    # Miscellaneous options
    parser_misc = parser.add_argument_group(title='Miscellaneous options')

    parser_misc.add_argument(
        '-V', '--verbose',
        help='Increase logging output verbosity (use up to 3 times)',
        action='count', default=0)

    parser_misc.add_argument(
        '-h', '--help',
        help='Display plugin help page and exit',
        action=_HelpAction)

    parser_misc.add_argument(
        '-v', '--version',
        help='Display plugin version',
        action='version', version=version)

    # Plugin mode parsers
    parser_mode = parser.add_subparsers(
        help='Specifies plugin execution mode', dest='mode')

    # Mode - mem-util
    mode_mem_util = parser_mode.add_parser(
        'mem-util',
        description='Checks the current memory utilization',
        epilog='API version support: 1.0 (full)')

    mode_mem_util.add_argument(
        '-w', '--warning',
        help='Warning threshold for utilization in percent (default: 70)',
        metavar='INT', type=int, default=70)

    # Completes argument parsing
    args = parser.parse_args()
    _log.debug('Provided command line arguments: "%s"' % args)

    return args

@nagiosplugin.guarded
def main():
    '''Main application function'''

    # Parses commandline arguments
    args = parse_args(description, version, developers, license) 


if __name__ == '__main__':
    main()
