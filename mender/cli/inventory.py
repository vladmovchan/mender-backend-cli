# The MIT License (MIT)
#
# Copyright (c) 2016 Maciej Borzecki
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

from mender.cli.utils import run_command, api_from_opts, do_simple_get, \
    do_request, errorprinter, jsonprinter, is_next_link_absent
from mender.client import inventory_url


def add_args(sub):
    pinvsub = sub.add_subparsers(help='Commands for inventory')
    sub.set_defaults(invcommand='')

    pdev = pinvsub.add_parser('device', help='Device commands')
    pdev.set_defaults(invcommand='device')
    pdev.set_defaults(invdevcommand='')

    pdevsub = pdev.add_subparsers(help='Device commands')

    pdev = pdevsub.add_parser('show', help='Show device')
    pdev.add_argument('device', help='Device ID')
    pdev.set_defaults(invdevcommand='show')

    pdevgroup = pdevsub.add_parser('group', help='Show/change device group assignment')
    pdevgroup.add_argument('device', help='Device ID')
    pdevgroup.add_argument('-s', '--group-set', help='Assign to group')
    pdevgroup.add_argument('-d', '--group-delete', help='Delete group')
    pdevgroup.set_defaults(invdevcommand='group')

    pdevlist = pdevsub.add_parser('list', help='List devices')
    pdevlist.add_argument('-a', '--attributes', default="id, updated", help='Csv attribute list to show')
    pdevlist.add_argument('-f', '--format', default='plain', choices=['plain', 'json'],
            help='Format Output')
    pdevlist.add_argument('-l', '--limit', default=500, help='Amount of records per page')
    pdevlist.add_argument('-p', '--page', default=1, help='Starting page number')
    pdevlist.add_argument('-1', '--single-page', default=False, action='store_true',
            help='Fetch just a single page')
    pdevlist.set_defaults(invdevcommand='list')

    pgr = pinvsub.add_parser('group', help='Group commands')
    pgr.set_defaults(invcommand='group')
    pgr.set_defaults(invgrcommand='')

    pgrsub = pgr.add_subparsers(help='Group commands')

    pglist = pgrsub.add_parser('list', help='List groups')
    pglist.set_defaults(invgrcommand='list')

    pg = pgrsub.add_parser('show', help='Show group devices')
    pg.add_argument('group', help='Group ID')
    pg.add_argument('-l', '--limit', default=500, help='Amount of records per page')
    pg.add_argument('-p', '--page', default=1, help='Starting page number')
    pg.add_argument('-1', '--single-page', default=False, action='store_true',
            help='Fetch just a single page')
    pg.set_defaults(invgrcommand='show')


def do_main(opts):
    commands = {
        'group': do_group,
        'device': do_device,
    }
    run_command(opts.invcommand, commands, opts)


def do_device(opts):
    commands = {
        'show': device_show,
        'group': device_group,
        'list': devices_list,
    }
    run_command(opts.invdevcommand, commands, opts)


def do_group(opts):
    commands = {
        'list': group_list,
        'show': group_show,
    }
    run_command(opts.invgrcommand, commands, opts)


def repack_attrs(attrs):
    # repack attributes to a dict with attribute name being the key, from
    # [{'name': <attribute name>, 'value': <attribute value>},..]
    if attrs:
        return {v['name']: v['value'] for v in attrs}
    return {}


def dump_device_attributes(data):
    logging.debug('device data: %r', data)
    attrs = repack_attrs(data.get('attributes', None))
    print('attributes:')
    for k in sorted(attrs.keys()):
        print('  {:20}: {}'.format(k, attrs[k]))
    print('last update:', data['updated_ts'])


def device_show(opts):
    url = inventory_url(opts.service, '/devices/{}'.format(opts.device))

    with api_from_opts(opts) as api:
        rsp = do_simple_get(api, url)
        logging.debug("%r", rsp.status_code)

        dump_device_attributes(rsp.json())

def device_group(opts):
    url = inventory_url(opts.service, '/devices/{}/group'.format(opts.device))
    if not opts.group_set and not opts.group_delete:
        with api_from_opts(opts) as api:
            do_simple_get(api, url)
    elif opts.group_set:
        group = {
            'group': opts.group_set,
        }
        method = 'PUT'
    elif opts.group_delete:
        url = inventory_url(opts.service, '/devices/{}/group/{}'.format(opts.device,
                                                                        opts.group_delete))
        group = {
            'group': opts.group_delete,
        }
        method = 'DELETE'

    with api_from_opts(opts) as api:
        do_request(api, url, method=method, success=204,
                   json=group)


def devices_list(opts):
    def devlist_printer(rsp):
        if opts.format == 'plain':
            for dev in rsp.json():
                attrs = repack_attrs(dev.get('attributes'))
                result = ""
                if opts.attributes:
                    for attribute in map(str.strip, opts.attributes.split(",")):
                        if attribute == 'id':
                            result += "{}={} ".format(attribute, dev['id'])
                        elif attribute == 'updated':
                            result += "{}={} ".format(attribute, dev['updated_ts'])
                        else:
                            result += "{}={} ".format(attribute, attrs.get(attribute, '<undefined>'))
                print(result)

        elif opts.format == 'json':
            jsonprinter(rsp)

    with api_from_opts(opts) as api:
        while True:
            url = inventory_url(opts.service, '/devices?per_page={}&page={}'
                    .format(opts.limit, opts.page))
            rsp = do_simple_get(api, url, printer=devlist_printer)
            if opts.single_page or is_next_link_absent(rsp):
                break
            opts.page += 1


def group_list(opts):
    url = inventory_url(opts.service, 'groups')
    with api_from_opts(opts) as api:
        do_simple_get(api, url)


def group_show(opts):
    with api_from_opts(opts) as api:
        while True:
            url = inventory_url(opts.service, 'groups/{}/devices?per_page={}&page={}'
                    .format(opts.group, opts.limit, opts.page))
            rsp = do_simple_get(api, url, printer=lambda rsp: [print(id) for id in rsp.json()])
            if opts.single_page or is_next_link_absent(rsp):
                break
            opts.page += 1
