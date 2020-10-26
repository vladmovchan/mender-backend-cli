# The MIT License (MIT)
#
# Copyright (c) 2017 Maciej Borzecki
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import logging
import requests

from mender.cli.utils import run_command, api_from_opts, do_simple_get, do_simple_delete, \
        do_request
from mender.client import authentication_url


def add_args(sub):
    pauth = sub.add_subparsers(help='Commands for device authentication')
    sub.set_defaults(authcommand='')

    pshow = pauth.add_parser('show', help='Show device')
    pshow.add_argument('device', help='Device ID')
    pshow.set_defaults(authcommand='show')

    plist = pauth.add_parser('list', help='List devices')
    plist.add_argument('-s', '--status', default='',
            choices=['accepted', 'rejected', 'preauthorized', 'pending'],
            help='list devices with specified status')
    plist.add_argument('-l', '--limit', default=500, help='Amount of records per page')
    plist.add_argument('-p', '--page', default=1, help='Starting page number')
    plist.add_argument('-1', '--single-page', default=False, action='store_true',
            help='Fetch just a single page')
    plist.add_argument('-P', '--printer', default="brief", choices=PRINT_MAP.keys(),
            help='Print function')
    plist.set_defaults(authcommand='list')

    pcount = pauth.add_parser('count', help='Count devices with given status')
    pcount.add_argument('-s', '--status', default='',
            choices=['accepted', 'rejected', 'preauthorized', 'pending'],
            help='count devices with specified status')
    pcount.set_defaults(authcommand='count')

    pdelete = pauth.add_parser('delete', help='Delete device')
    pdelete.add_argument('device', help='Device ID')
    pdelete.set_defaults(authcommand='delete')

    paccept = pauth.add_parser('accept', help='Accept device')
    paccept.add_argument('device', help='Device ID')
    paccept.add_argument('-a', '--aid',
            help='Explicitly specify device authentication data set id')
    paccept.set_defaults(authcommand='accept')

    preject = pauth.add_parser('reject', help='Reject device')
    preject.add_argument('device', help='Device ID')
    preject.add_argument('-a', '--aid',
            help='Explicitly specify device authentication data set id')
    preject.set_defaults(authcommand='reject')


def do_main(opts):
    commands = {
        'list': list_devices,
        'count': count_devices,
        'show': show_device,
        'delete': delete_device,
        'accept': lambda opts: set_device_auth_status(opts, 'accepted'),
        'reject': lambda opts: set_device_auth_status(opts, 'rejected'),
    }
    run_command(opts.authcommand, commands, opts)


def dump_device_brief(data):
    logging.debug('device auth data: %r', data)
    print('device ID: %s' % data['id'])
    print('    created:  %s' % data['created_ts'])
    print('    auth sets: %s' % ', '.join(['{} ({})'.format(aset['id'], aset['status'])
                                           for aset in
                                           data.get('auth_sets', [])]))

def dump_device(data):
    logging.debug('device auth data: %r', data)
    print('device ID: %s' % data['id'])
    print('    created:  %s' % data['created_ts'])
    print('    auth sets:')
    for aset in data.get('auth_sets', []):
        print('       id: %s' % aset['id'])
        print('       status: %s' % aset['status'])
        print('       identity data: %s' % aset['identity_data'])
        key_lines = aset['pubkey'].split('\n')
        print('       key:', key_lines[0])
        for l in key_lines[1:]:
            print(' ' * 11, l)


PRINT_MAP = {'brief': dump_device_brief,
             'full': dump_device}

def show_device(opts):
    url = authentication_url(opts.service, '/devices/{}'.format(opts.device))
    with api_from_opts(opts) as api:
        rsp = do_simple_get(api, url,
                            printer=lambda rsp: dump_device(rsp.json()))


def list_devices(opts):
    with api_from_opts(opts) as api:
        while True:
            url = authentication_url(opts.service, '/devices?status={}&per_page={}&page={}'
                    .format(opts.status, opts.limit, opts.page))
            rsp = do_simple_get(api, url, printer=lambda rsp:
                    [PRINT_MAP[opts.printer](dev) for dev in rsp.json()])
            if (opts.single_page
                or 'Link' not in rsp.headers
                or not list(filter(lambda link: link['rel'] == 'next',
                    requests.utils.parse_header_links(rsp.headers['Link'])))):
                break
            opts.page += 1

def delete_device(opts):
    url = authentication_url(opts.service, '/devices/{}'.format(opts.device))
    with api_from_opts(opts) as api:
        rsp = do_simple_delete(api, url)

def set_device_auth_status(opts, status):
    if opts.aid is None:
        url = authentication_url(opts.service, '/devices/{}'.format(opts.device))
        with api_from_opts(opts) as api:
            rsp = do_simple_get(api, url, printer=lambda rsp: None).json()
        if 'auth_sets' not in rsp:
            logging.error('`auth_sets` is absent in the reply')
            logging.error('\ttry to specify authentication data set id explicitly')
            return
        if len(rsp['auth_sets']) == 0:
            logging.error('`auth_sets` array is empty in the reply')
            return
        if len(rsp['auth_sets']) > 1:
            logging.error('There are more than one authentication data set available for the device')
            logging.error('\tplease specify explicitly which one to use')
            logging.error('\t%s' % ', '.join(['{} ({})'.format(aset['id'], aset['status'])
                                               for aset in rsp.get('auth_sets', [])]))
            return
        opts.aid = rsp['auth_sets'][0]['id']
        logging.debug('obtained authentication data set id: %s', opts.aid)
    url = authentication_url(opts.service,
            '/devices/{}/auth/{}/status'.format(opts.device, opts.aid))
    logging.debug('device auth URL: %s', url)
    with api_from_opts(opts) as api:
        do_request(api, url, method='PUT', json={'status': status})

def count_devices(opts):
    url = authentication_url(opts.service, '/devices/count?status={}'.format(opts.status))
    with api_from_opts(opts) as api:
        rsp = do_simple_get(api, url)
