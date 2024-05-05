#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2014, 2015 Mitch Garnaat http://garnaat.org/
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

from datetime import datetime
import base64

import click

from kappa.context import Context

pass_ctx = click.make_pass_decorator(Context)


@click.group()
@click.option(
    '--config',
    default='kappa.yml',
    type=click.File('rb'),
    envvar='KAPPA_CONFIG',
    help='Name of config file (default is kappa.yml)'
)
@click.option(
    '--debug/--no-debug',
    default=False,
    help='Turn on debugging output'
)
@click.option(
    '--env',
    default='dev',
    help='Specify which environment to work with (default dev)'
)
@click.option(
    '--record-path',
    type=click.Path(exists=True, file_okay=False, writable=True),
    help='Uses placebo to record AWS responses to this path'
)
@click.pass_context
def cli(ctx, config=None, debug=False, env=None, record_path=None):
    ctx.obj = Context(config, env, debug, record_path)


@cli.command()
@pass_ctx
def deploy(ctx):
    """Deploy the Lambda function and any policies and roles required"""
    click.echo('deploying')
    ctx.deploy()
    click.echo('done')


@cli.command()
@click.argument('data_file', type=click.File('r'))
@pass_ctx
def invoke(ctx, data_file):
    """Invoke the command synchronously"""
    click.echo('invoking')
    response = ctx.invoke(data_file.read())
    log_data = base64.b64decode(response['LogResult'])
    click.echo(log_data)
    click.echo('Response:')
    click.echo(response['Payload'].read())
    click.echo('done')


@cli.command()
@pass_ctx
def test(ctx):
    """Test the command synchronously"""
    click.echo('testing')
    ctx.test()
    click.echo('done')


@cli.command()
@pass_ctx
def tail(ctx):
    """Show the last 10 lines of the log file"""
    click.echo('tailing logs')
    for e in ctx.tail()[-10:]:
        ts = datetime.utcfromtimestamp(e['timestamp'] // 1000).isoformat()
        click.echo("{}: {}".format(ts, e['message']))
    click.echo('done')


@cli.command()
@pass_ctx
def status(ctx):
    """Print a status of this Lambda function"""
    status = ctx.status()
    click.echo(click.style('Policy', bold=True))
    if status['policy']:
        line = '    {} ({})'.format(
            status['policy']['PolicyName'],
            status['policy']['Arn'])
        click.echo(click.style(line, fg='green'))
    click.echo(click.style('Role', bold=True))
    if status['role']:
        line = '    {} ({})'.format(
            status['role']['RoleName'],
            status['role']['Arn'])
        click.echo(click.style(line, fg='green'))
    click.echo(click.style('Function', bold=True))
    if status['function']:
        line = '    {} ({})'.format(
            status['function']['Configuration']['FunctionName'],
            status['function']['Configuration']['FunctionArn'])
        click.echo(click.style(line, fg='green'))
    else:
        click.echo(click.style('    None', fg='green'))
    click.echo(click.style('Event Sources', bold=True))
    if status['event_sources']:
        for event_source in status['event_sources']:
            if event_source:
                arn = event_source.get('EventSourceArn')
                state = event_source.get('State', 'Enabled')
                line = '    {}: {}'.format(arn, state)
                click.echo(click.style(line, fg='green'))
            else:
                click.echo(click.style('    None', fg='green'))


@cli.command()
@pass_ctx
def delete(ctx):
    """Delete the Lambda function and related policies and roles"""
    click.echo('deleting')
    ctx.delete()
    click.echo('done')


@cli.command()
@click.argument('command',
                type=click.Choice(['list', 'enable', 'disable']))
@pass_ctx
def event_sources(ctx, command):
    """List, enable, and disable event sources specified in the config file"""
    if command == 'list':
        click.echo('listing event sources')
        event_sources = ctx.list_event_sources()
        for es in event_sources:
            click.echo('arn: {}'.format(es['arn']))
            click.echo('starting position: {}'.format(es['starting_position']))
            click.echo('batch size: {}'.format(es['batch_size']))
            click.echo('enabled: {}'.format(es['enabled']))
        click.echo('done')
    elif command == 'enable':
        click.echo('enabling event sources')
        ctx.enable_event_sources()
        click.echo('done')
    elif command == 'disable':
        click.echo('disabling event sources')
        ctx.disable_event_sources()
        click.echo('done')
