#!/usr/bin/env python3
"""Isolated Docker soak; no production mounts, tokens or credentials in reports."""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import time


def command(*args, check=True):
    try:
        p = subprocess.run(args, capture_output=True, timeout=60)
    except subprocess.TimeoutExpired:
        raise RuntimeError('command timed out (arguments redacted)') from None
    if check and p.returncode:
        # Do not include argv: enrollment arguments may contain a token.
        raise RuntimeError(p.stderr.decode(errors='replace')[-1500:])
    return p

def handle_termination():
    def stop(signum, frame):
        raise RuntimeError('interrupted by signal ' + str(signum))
    signal.signal(signal.SIGTERM, stop)


def main():
    handle_termination()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--duration', type=int, default=1800, help='steady-state seconds, excluding fault recovery')
    args = parser.parse_args()
    if args.duration < 60:
        parser.error('duration must be at least 60 seconds')
    args.output.mkdir(parents=True, exist_ok=False)
    os.chmod(args.output, 0o700)
    prefix = 'veilink-soak-' + secrets.token_hex(4)
    network = prefix + '-net'
    names = {role: prefix + '-' + role for role in ('master', 'server', 'client', 'target')}
    created = []
    events = []
    started = time.monotonic()
    password = secrets.token_urlsafe(24)
    csrf = ''
    summary = {'passed': False, 'duration_requested': args.duration, 'image': args.image, 'events': events}

    def event(kind, **values):
        row = dict(seconds=round(time.monotonic() - started, 2), event=kind, **values)
        events.append(row)
        with (args.output / 'events.jsonl').open('a') as f:
            f.write(json.dumps(row) + '\n')
        print(json.dumps(row), flush=True)

    def api(path, body=None, method=None, expected=200):
        argv = ['docker', 'exec', names['master'], 'curl', '--noproxy', '*', '-sS', '--max-time', '8',
                '-b', '/tmp/soak-cookie', '-c', '/tmp/soak-cookie', '-H', 'Content-Type: application/json',
                '-H', 'X-CSRF-Token: ' + csrf, '-w', '\n%{http_code}']
        if method:
            argv += ['-X', method]
        if body is not None:
            argv += ['-d', json.dumps(body)]
        raw = command(*argv, 'http://127.0.0.1:8443/api' + path).stdout.decode()
        data, status = raw.rsplit('\n', 1)
        if int(status) != expected:
            raise RuntimeError('API %s: status %s' % (path, status))
        return json.loads(data) if data else None

    def login():
        nonlocal csrf
        csrf = api('/login', {'username': 'soak', 'password': password})['csrf']

    def wait(label, fn, timeout=90):
        start = time.monotonic()
        last = ''
        while time.monotonic() - start < timeout:
            try:
                value = fn()
                if value:
                    event(label, recovery_seconds=round(time.monotonic() - start, 2))
                    return value
            except (RuntimeError, ValueError, KeyError) as e:
                last = str(e)
            time.sleep(2)
        raise RuntimeError(label + ' timed out: ' + last)

    def converged():
        ns = api('/nodes')
        return len(ns) == 2 and all(n['desired_revision'] > 0 and n['desired_revision'] == n['applied_revision']
                                   and not n['error'] and 0 <= time.time() - n['last_seen'] < 30 for n in ns)

    def probe():
        p = command('docker', 'exec', names['master'], 'curl', '--noproxy', '*', '-fsS', '--max-time', '4',
                    'http://server:18080/', check=False)
        return p.returncode == 0 and p.stdout.strip() == b'veilink-soak-business'

    try:
        command('docker', 'network', 'create', '--internal', network)
        # The image is the same role-selectable product in all three roles.
        command('docker', 'run', '-itd', '--name', names['master'], '--network', network, '--network-alias', 'master',
                '--restart', 'unless-stopped', '-e', 'TZ=Asia/Shanghai', args.image,
                'master', '-listen-addr', '0.0.0.0:8443')
        created.append(names['master'])
        command('docker', 'run', '-d', '--name', names['target'], '--network', network, '--network-alias', 'target',
                'node:alpine', 'node', '-e',
                "require('http').createServer((q,s)=>s.end('veilink-soak-business')).listen(8080,'0.0.0.0')")
        created.append(names['target'])
        wait('master_ready', lambda: api('/setup'))
        api('/register', {'username': 'soak', 'password': password}, expected=201)
        login()
        cert = api('/nodes/generate', {'role': 'server', 'kind': 'certificate', 'host': 'server', 'ttl_days': 1})
        server = api('/nodes', {'name': 'soak-server', 'role': 'server', 'address': 'server', 'port': 18444,
                     'tunnel': dict(transport_security='tls', listen_host='0.0.0.0', listen_port=18444,
                                    **{k: cert[k] for k in ('cert_pem', 'key_pem', 'ca_pem')})})
        client = api('/nodes', {'name': 'soak-client', 'role': 'client'})
        mapping = api('/mappings', {'name': 'soak-http', 'server_id': server['id'], 'client_id': client['id'],
                     'network': 'tcp', 'pool': 1, 'mux': False, 'mux_type': '', 'listen_host': '0.0.0.0',
                     'listen_port': 18080, 'target_host': 'target', 'target_port': 8080, 'enabled': True})
        for role, node in [('server', server), ('client', client)]:
            token = api('/nodes/' + node['id'] + '/enroll', {'ttl_seconds': 3600})['token']
            command('docker', 'run', '-itd', '--name', names[role], '--network', network, '--network-alias', role,
                    '--restart', 'unless-stopped', '-e', 'TZ=Asia/Shanghai', args.image, role,
                    '-master-addr', 'master:8443', '-node-id', node['id'], '-enroll-token', token)
            created.append(names[role])
        wait('initial_convergence', converged)
        wait('initial_business', probe)
        # Network partition longer than both stream timeout (45s) and online window (90s).
        command('docker', 'network', 'disconnect', network, names['client'])
        event('partition_started', role='client', seconds_planned=100)
        time.sleep(100)
        ns = api('/nodes')
        c = next(n for n in ns if n['id'] == client['id'])
        age = time.time() - c['last_seen']
        if age < 90 or probe():
            raise RuntimeError('partition did not expire heartbeat / stop business')
        event('partition_observed', heartbeat_age=round(age, 1), business_available=False)
        mapping['pool'] = 2
        api('/mappings/' + mapping['id'], mapping, 'PUT')
        c = next(n for n in api('/nodes') if n['id'] == client['id'])
        if c['desired_revision'] <= c['applied_revision']:
            raise RuntimeError('offline configuration drift was not visible')
        event('offline_drift', desired=c['desired_revision'], applied=c['applied_revision'])
        command('docker', 'network', 'connect', '--alias', 'client', network, names['client'])
        wait('partition_recovered', converged)
        wait('partition_business_recovered', probe)
        for role in ('client', 'server', 'master'):
            previous = {n['id']: n['last_seen'] for n in api('/nodes')}
            command('docker', 'restart', names[role])
            event('process_restart', role=role)
            if role == 'master':
                wait('master_relogin', lambda: (login() or True))
            wait(role + '_new_heartbeat', lambda: all(n['last_seen'] > previous[n['id']] for n in api('/nodes')))
            wait(role + '_restart_converged', converged)
            wait(role + '_restart_business', probe)
        end = time.monotonic() + args.duration
        cycles = samples = 0
        last_seen = {n['id']: n['last_seen'] for n in api('/nodes')}
        while time.monotonic() < end:
            mode = ('', 'smux', 'yamux', 'h2mux')[cycles % 4]
            mapping.update(mux=bool(mode), mux_type=mode, pool=1 + cycles % 2)
            api('/mappings/' + mapping['id'], mapping, 'PUT')
            wait('rollout_converged', converged)
            wait('rollout_business', probe)
            for _ in range(6):
                if not probe():
                    raise RuntimeError('steady-state business request failed')
                ns = api('/nodes')
                if any(n['error'] or time.time() - n['last_seen'] >= 45 for n in ns):
                    raise RuntimeError('heartbeat/error during steady state')
                samples += 1
                time.sleep(5)
            ns = api('/nodes')
            if any(n['last_seen'] <= last_seen[n['id']] for n in ns):
                raise RuntimeError('heartbeat failed to advance')
            last_seen = {n['id']: n['last_seen'] for n in ns}
            event('steady_cycle', mux=mode or 'off', nodes=[{k: n[k] for k in ('role', 'desired_revision', 'applied_revision', 'last_seen')} for n in ns])
            cycles += 1
        summary['roles'] = {}
        for role in ('master', 'server', 'client'):
            content = command('docker', 'exec', names[role], 'sh', '-c', 'test -s /usr/local/html/index.html && sha256sum /usr/local/bin/veilink && /usr/local/bin/docker-healthcheck.sh').stdout.decode().strip()
            health = command('docker', 'inspect', '--format', '{{.State.Health.Status}}', names[role]).stdout.decode().strip()
            if health != 'healthy':
                raise RuntimeError(role + ' not healthy')
            summary['roles'][role] = dict(content=content, health=health)
        if len({v['content'] for v in summary['roles'].values()}) != 1:
            raise RuntimeError('role binary hashes differ')
        summary.update(passed=True, cycles=cycles, business_samples=samples)
    except Exception as e:
        summary['error'] = str(e)
        event('failure', error=str(e))
        raise
    finally:
        summary['elapsed_seconds'] = round(time.monotonic() - started, 2)
        for name in created:
            # Runtime logs must never contain enrollment tokens; avoid docker inspect argv.
            p = command('docker', 'logs', '--tail', '200', name, check=False)
            (args.output / (name.rsplit('-', 1)[-1] + '.log')).write_bytes(p.stdout + p.stderr)
        for name in reversed(created):
            command('docker', 'rm', '-f', name, check=False)
        command('docker', 'network', 'rm', network, check=False)
        summary['cleanup_remaining'] = command('docker', 'ps', '-aq', '--filter', 'name=' + prefix, check=False).stdout.decode().strip()
        (args.output / 'result.json').write_text(json.dumps(summary, indent=2) + '\n')


if __name__ == '__main__':
    main()
