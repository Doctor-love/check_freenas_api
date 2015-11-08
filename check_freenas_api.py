#!/usr/bin/env python

'''>>>>>>>> check_freenas_api - Monitoring plugin for FreeNAS systems <<<<<<<<
This plugin utilizes the REST API and have been tested on FreeNAS 9.3.1'''

developers = ['Joel Rangsmo <joel@rangsmo.se>']
description = __doc__
version = '0.2'
license = 'GPLv2'

try:
    import logging
    import argparse
    import requests
    import nagiosplugin

except ImportError as missing:
    print(
        'UNKNOWN - Could not import all required modules: "%s".\n' % missing +
        'Installation with PIP: "pip install argparse requests nagiosplugin"')

    exit(3)

_log = logging.getLogger('nagiosplugin')

# -----------------------------------------------------------------------------
# Exception related code

class APIError(Exception):
    '''All FreeNAS API exceptions inherit from this one'''

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class ConnectionError(APIError):
    '''Exceptions related to API connection and network issues'''

class ResponseError(APIError):
    '''Exceptions related to issues with API response data'''

class PluginError(Exception):
    '''Exceptions related to plugin logic issues'''

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

# -----------------------------------------------------------------------------
# FreeNAS API object related code

class FreeNASSession(object):
    '''Object used for communicating with the FreeNAS RESTful API'''

    def __init__(self, server=None, user=None, password=None, **kwargs):
        self.server = server
        self.user = user
        self.password = password

        self.port = kwargs.get('port', 443)
        self.verify = kwargs.get('verify', True)
	self.timeout = kwargs.get('timeout', 50)
        self.api_version = kwargs.get('api_version', '1.0')

        self.base_path = (
            'https://%s:%i/api/v%s/' % (server, self.port, self.api_version))

        # Creates requests session object
        self.session = requests.Session()

        self.session.auth = (self.user, self.password)
        self.session.timeout = self.timeout
        self.session.verify = self.verify

        self.session.headers.update({'content-type': 'application/json'})
        self.session.headers.update({'accept': 'application/json'})

        # Disables warnings if certificate verification is disabled
        if not self.verify:
            try:
                requests.packages.urllib3.disable_warnings()

            except:
                _log.debug('Failed to disable urllib3 warnings')

    def get(self, sub_path):
        '''Retrive data from specified API path.
        Returns the decoded response and raises APIError in case of issues'''

        _log.debug('Retriving data from %s%s...' % (self.base_path, sub_path))

        try:
            query = self.session.get(self.base_path + sub_path)
    
        except requests.exceptions.Timeout:
            raise ConnectionError(
                'Connection to "%s:%i" timed out after %i seconds'
                % (self.server, self.port, self.timeout))

        # Work-around for https://github.com/shazow/urllib3/issues/556
        except (requests.exceptions.SSLError, TypeError):
            raise ConnectionError('Failed to verify server certificate')

        except requests.exceptions.Timeout:
            raise ConnectionError(
                'Could not connect to "%s:%i"' % (self.server, self.port))

        except requests.exceptions.RequestException as error_msg:
            raise ConnectionError(
                'Failed to connect to FreeNAS API: "%s"' % error_msg)

        except Exception as error_msg:
            raise ConnectionError(
                'Failed to connect to FreeNAS API: "%s"' % error_msg)

        _log.debug('Raw query response: "%s"' % str(query.text))

        status = query.status_code
        _log.debug('Checking response status code %i' % status)

        if status == 200 or status == 201:
            _log.debug('Retrived acceptable status code')

        elif status == 401 or status == 403:
            raise ResponseError(
                'User, password or permissions was not accepted by FreeNAS')

        elif status == 404:
            raise ResponseError(
                'Resource "%s%s" was not found' % (self.base_path, sub_path))

        elif status == 503:
            _log.debug('Response body text: "%s"' % str(query.text))
            raise ResponseError(
                'FreeNAS API generated internal server error')

        else:
            raise ResponseError(
                '"%i" is not a know FreeNAS API status code' % status)

        _log.debug('Decoding/Loading JSON from query response...')

        try:
            return query.json()

        except Exception as error_msg:
            _log.error(
                'Failed to decode JSON data in response: "%s"' % error_msg)

            raise ResponseError('Failed to decode query response data')

# -----------------------------------------------------------------------------
# Argument parsing related code

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


def split_string(list_string):
    '''Split a comma separated string argument into a list'''
    
    try:
        # Are there any commas escaped in the string?
        list_string = list_string.replace('\\,', '9-_-!-flgk34z.:.q!x')

        argument_list = list_string.split(',')

        # Restore the escaped commas
        for index, argument in enumerate(argument_list):
            argument_list[index] = argument.replace('9-_-!-flgk34z.:.q!x', ',')
    
    except Exception as error_msg:
        raise argparse.ArgumentTypeError(
            'Failed to convert comma seperated string: "%s"' % error_msg)

    return argument_list


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
        '-t', '--timeout',
        help='Plugin timeout in seconds (default: %(default)i)',
        metavar='SECONDS', type=int, default=55)

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

    # Plugin check mode parsers
    parser_mode = parser.add_subparsers(
        help='Specifies plugin execution mode', dest='mode')

    # -------------------------------------------------------------------------
    mode_vol_usage = parser_mode.add_parser(
        'volume-usage',
        description='Checks the current volume usage percentage',
        epilog='API version support: 1.0 (full)')

    mode_vol_usage.add_argument(
        '-v', '--volume', dest='volume_name',
        help='Volume specified by friendly name',
        metavar='dozer', type=str)

    mode_vol_usage.add_argument(
        '-i', '--include',
        help='Comma separate list of volumes to include in usage check, '
        'specified by friendly name',
        metavar='tank,apoc', type=split_string)

    mode_vol_usage.add_argument(
        '-e', '--exclude',
        help='Comma separate list of volumes to exclude from usage check, '
        'specified by friendly name',
        metavar='mouse,neo', type=split_string)

    mode_vol_usage.add_argument(
        '-w', '--warning',
        help='Warning threshold for usage in percent (default: %(default)s)',
        metavar='RANGE', type=str, default='70')

    mode_vol_usage.add_argument(
        '-c', '--critical',
        help='Warning threshold for usage in percent (default: %(default)s)',
        metavar='RANGE', type=str, default='90')

    mode_vol_usage.add_argument(
        '-b', '--brief-status',
        help='Provide brief usage oveview in status output',
        action='store_true', default=False)

    # -------------------------------------------------------------------------
    mode_sys_alerts = parser_mode.add_parser(
        'system-alerts',
        description='Checks if unhandled system alerts have been triggered',
        epilog='API version support: 1.0 (full)')

    mode_sys_alerts.add_argument(
        '-e', '--exclude',
        help='Comma separate list of alert messages to exclude',
        metavar='"smartd is not running"', type=split_string)

    mode_sys_alerts.add_argument(
        '-b', '--brief-status',
        help='Provide brief alert oveview in status output',
        action='store_true', default=False)

    # -------------------------------------------------------------------------
    # Completes argument parsing
    return parser.parse_args()

# -----------------------------------------------------------------------------
# Acquisition, evaluation and presentation for check modes.
# Documentation: https://pythonhosted.org/nagiosplugin/tutorial/index.html

# -----------------------------------------------------------------------------
# Mode - "volume-usage"
class VolumeUsageCheck(nagiosplugin.Resource):
    '''Checks the usage percentage of volumes'''

    def __init__(
        self, session=None, api_version=None,
        volume_name=None, include=None, exclude=None):

        self.session = session
        self.api_version = api_version
        self.volume_name = volume_name
        self.include = include
        self.exclude = exclude

    def probe(self):
        _log.info('Querying volume usage percentage')

        volumes = self.session.get('storage/volume/')

        try:
            _log.debug('Extracting usage data for %i volumes' % len(volumes))

            for volume in volumes:
                name = str(volume['vol_name'])

                _log.debug('Checking filtering options for "%s"' % name)

                # Logic to include or exclude volume
                if self.volume_name and name != self.volume_name:
                    _log.debug('"%s" did not match specified volume' % name)
                    continue

                elif self.include and not name in self.include:
                    _log.debug('"%s" should not be included' % name)
                    continue

                elif self.exclude and name in self.exclude:
                    _log.debug('"%s" should be excluded' % name)
                    continue

                # FreeNAS API ain't all that robot friendly...
                if volume['used_pct'] == 'Error':
                    raise ResponseError(
                        'Checked volume "%s" is experiencing issues' % name)

                usage = int(volume['used_pct'].replace('%', ''))

                yield nagiosplugin.Metric(
                    name=name, context='usage',
                    value=usage, uom='%', min=0, max=100)

                if self.volume_name and name == self.volume_name:
                    _log.info('Found volume "%s" - breaking loop' % name)
                    break

        except ResponseError as error_msg:
            raise PluginError('Failed to extract volume usage: %s' % error_msg)

        except Exception as error_msg:
            _log.error('Failed to extract query data: "%s"' % error_msg)
            raise PluginError('Failed to extract volume usage data from query')


class VolumeUsageSummary(nagiosplugin.Summary):
    '''Summarises the usage percentage of volumes'''

    def __init__(self, brief_status=None):
        self.brief_status = brief_status

    def ok(self, results):
        _log.debug('Building volume usage summary for status output')

        if self.brief_status and int(results.most_significant_state) == 0:
            return 'Usage levels of all checked volumes are acceptable'

        # Builds detalied status output message
        overall_status = 'Volume usage status: '

        for result in results:
            overall_status += str(result) + ', '

        # Removes the trailing space and comma characters
        return overall_status[:-2]

    def problem(self, results):
        # Work-around if you wish to use the same summary for all states
        return self.ok(results)

    def empty(self):
        return 'Found no volumes matching filtering requirements'

# -----------------------------------------------------------------------------
# Mode - "system-alerts"
class SystemAlertsCheck(nagiosplugin.Resource):
    '''Checks if any unhandled system alerts exist'''

    def __init__(self, session=None, api_version=None, exclude=None):
        self.session = session
        self.api_version = api_version
        self.exclude = exclude

    def probe(self):
        _log.info('Querying list of system alerts')

        alerts = self.session.get('system/alert/')

        try:
            _log.debug('Extracting status for %i alerts' % len(alerts))

            triggered_alerts = 0

            for alert in alerts:
                message = str(alert['message']).strip()
                dismissed = bool(alert['dismissed'])

                _log.debug('Checking filtering for message "%s"' % message)

                if dismissed:
                    _log.debug('Alert has already been acknowledged')
                    continue

                elif self.exclude and message in self.exclude:
                    _log.debug('Matched "%s" - excluding message' % message)
                    continue

                level = str(alert['level'])

                yield nagiosplugin.Metric(
                    name=message, context='alert', value=level)

                triggered_alerts += 1

        except Exception as error_msg:
            _log.error('Failed to extract query data: "%s"' % error_msg)
            raise PluginError('Failed to extract system alert data from query')

        # Strange looking work-around for *INSERT BUG ID*
        if triggered_alerts is 0:
            yield nagiosplugin.Metric(
                name='Found no unhandled alerts', context='alert', value='')


class SystemAlertsContext(nagiosplugin.Context):
    '''Evaluates the status of system alerts'''

    def evaluate(self, metric, resource):
        _log.debug('Checking status of alert "%s"' % metric.name)

        # If no unhandled system alerts exist
        if not metric.value:
            return self.result_cls(
                nagiosplugin.state.Ok, 'No alerts exist', metric)

        elif metric.value == 'OK':
            return self.result_cls(
                nagiosplugin.state.Ok, '"%s"' % metric.name, metric)

        elif metric.value == 'WARN':
            return self.result_cls(
                nagiosplugin.state.Warn, '"%s"' % metric.name, metric)

        elif metric.value == 'CRIT':
            return self.result_cls(
                nagiosplugin.state.Critical, '"%s"' % metric.name, metric)

        else:
            return self.result_cls(
                nagiosplugin.state.Unknown,
                'Alert level "%s" is not known' % str(metric.value), metric)


class SystemAlertsSummary(nagiosplugin.Summary):
    '''Summarises the status of triggered system alerts'''

    def __init__(self, brief_status=None):
        self.brief_status = brief_status

    def ok(self, results):
        return self.empty()

    def problem(self, results):
        _log.debug('Building problem output for system alerts')

        worst_state = str(results.most_significant_state)

        if self.brief_status:
            _log.debug('Building brief status output message')

            return (
                'Found %i unhandled system alert(s) with status %s'
                % (len(results.most_significant), worst_state))

        # Generates detailed status output
        overall_status = 'System alerts in worst state: '

        for result in results.most_significant:
            if worst_state == "Unknown":
                return 'Encountered problems in alert check: %s' % str(result)

            overall_status += str(result) + ', '

        # Removes the trailing space and comma characters
        return overall_status[:-2]

    def empty(self):
        return 'Found no unhandled system alerts'

# -----------------------------------------------------------------------------
# Main function related code

@nagiosplugin.guarded
def main():
    '''Main application function'''

    # Parses commandline arguments
    args = parse_args(description, version, developers, license) 

    # Creates FreeNAS API session
    session = FreeNASSession(
        server=args.host, port=args.port, timeout=args.timeout - 2,
        verify=args.verify, user=args.user, password=args.password,
        api_version=args.api_version)

    # Check mode selection
    if args.mode == 'volume-usage':
        check = nagiosplugin.Check(
            VolumeUsageCheck(
                session=session, api_version=args.api_version,
                volume_name=args.volume_name,
                include=args.include, exclude=args.exclude),

        nagiosplugin.ScalarContext('usage', args.warning, args.critical),
        VolumeUsageSummary(args.brief_status))

    elif args.mode == 'system-alerts':
        check = nagiosplugin.Check(
            SystemAlertsCheck(
                session=session, api_version=args.api_version,
                exclude=args.exclude),

        SystemAlertsContext('alert'),
        SystemAlertsSummary(args.brief_status))

    # Run the specified check mode
    check.name = 'FN'
    check.main(timeout=args.timeout, verbose=args.verbose)


if __name__ == '__main__':
    main()
