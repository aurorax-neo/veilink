#!/usr/bin/env python3
"""Real nginx TLS termination -> HTTP API and h2c bidirectional gRPC check."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shlex
import time
from soak import command, handle_termination


def main():
    handle_termination()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image', required=True)
    p.add_argument('--nginx-image', default='nginx:alpine')
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    a.output = a.output.resolve()
    a.output.mkdir(parents=True, exist_ok=False)
    os.chmod(a.output, 0o700)
    prefix = 'veilink-proxy-' + secrets.token_hex(4)
    network = prefix + '-net'
    names = {r: prefix + '-' + r for r in ('master', 'nginx', 'server', 'client')}
    created = []
    csrf = ''
    result = {'passed': False}
    certs = a.output / 'certs'
    command('go', 'run', './tools/devcert', '-out', str(certs), '-hosts', 'panel.test')
    os.chmod(certs / 'ca.pem', 0o644)  # Public CA only; private key remains restricted.
    conf = '''events {}
http {
 map $http_origin $veilink_origin {
  default $http_origin;
  "https://panel.test" "http://panel.test";
 }
 server {
  listen 443 ssl;
  http2 on;
  server_name panel.test;
  ssl_certificate /certs/cert.pem;
  ssl_certificate_key /certs/key.pem;
  location /veilink.control.v1.Control/ {
   grpc_pass grpc://master:8443;
   grpc_set_header Host panel.test;
   grpc_read_timeout 3600s;
   grpc_send_timeout 3600s;
  }
  location / {
   proxy_pass http://master:8443;
   proxy_http_version 1.1;
   proxy_set_header Host panel.test;
   proxy_set_header Origin $veilink_origin;
   proxy_set_header X-Forwarded-Proto $scheme;
   proxy_set_header X-Forwarded-For $remote_addr;
   proxy_cookie_flags veilink_session secure httponly samesite=strict;
  }
 }
}
'''
    (a.output / 'nginx.conf').write_text(conf)

    def request(path, body=None, expected=200, origin='https://panel.test', token=True, headers=False):
        args = ['docker', 'exec', names['master'], 'curl', '--noproxy', '*', '--cacert', '/tmp/ca.pem', '-sS',
                '--max-time', '10', '-b', '/tmp/cookie', '-c', '/tmp/cookie', '-H', 'Content-Type: application/json',
                '-H', 'Origin: ' + origin, '-w', '\n%{http_code}']
        if token:
            args += ['-H', 'X-CSRF-Token: ' + csrf]
        if headers:
            args += ['-D', '-']
        if body is not None:
            args += ['-d', json.dumps(body)]
        raw = command(*args, 'https://panel.test' + path).stdout.decode()
        data, status = raw.rsplit('\n', 1)
        if int(status) != expected:
            raise RuntimeError(path + ': HTTP ' + status)
        return data if headers else (json.loads(data) if data else None)

    try:
        command('docker', 'network', 'create', '--internal', network)
        command('docker', 'run', '-itd', '--name', names['master'], '--network', network, '--network-alias', 'master',
                '--restart', 'unless-stopped', '-e', 'TZ=Asia/Shanghai', a.image, 'master', '-listen-addr', '0.0.0.0:8443')
        created.append(names['master'])
        command('docker', 'cp', str(certs / 'ca.pem'), names['master'] + ':/tmp/ca.pem')
        command('docker', 'run', '-d', '--name', names['nginx'], '--network', network, '--network-alias', 'panel.test',
                '-v', str(a.output / 'nginx.conf') + ':/etc/nginx/nginx.conf:ro', '-v', str(certs) + ':/certs:ro', a.nginx_image)
        created.append(names['nginx'])
        time.sleep(2)
        command('docker', 'exec', names['nginx'], 'nginx', '-t')
        request('/api/setup')
        # Browser-origin protections must survive TLS termination.
        password = secrets.token_urlsafe(24)
        credentials = {'username': 'proxy-check', 'password': password}
        request('/api/register', credentials, expected=403, origin='https://evil.example')
        request('/api/register', credentials, expected=201)
        login = request('/api/login', credentials, headers=True)
        header, body = login.split('\r\n\r\n', 1)
        cookie = next(x for x in header.splitlines() if x.lower().startswith('set-cookie:')).lower()
        assert all(x in cookie for x in ('secure', 'httponly', 'samesite=strict'))
        csrf = json.loads(body)['csrf']
        request('/api/nodes', {'name': 'blocked', 'role': 'client'}, expected=403, token=False)
        request('/api/nodes', {'name': 'blocked', 'role': 'client'}, expected=403, origin='https://evil.example')
        html = command('docker', 'exec', names['master'], 'curl', '--noproxy', '*', '--cacert', '/tmp/ca.pem', '-fsS', 'https://panel.test/').stdout
        assert b'<html' in html
        untrusted = command('docker', 'exec', names['master'], 'curl', '--noproxy', '*', '-fsS', 'https://panel.test/api/setup', check=False)
        assert untrusted.returncode == 60
        cert = request('/api/nodes/generate', {'role': 'server', 'kind': 'certificate', 'host': 'server', 'ttl_days': 1})
        for role in ('server', 'client'):
            body = {'name': 'proxy-' + role, 'role': role}
            if role == 'server':
                body.update(address='server', port=18444, tunnel=dict(transport_security='tls', listen_host='0.0.0.0', listen_port=18444,
                            **{k: cert[k] for k in ('cert_pem', 'key_pem', 'ca_pem')}))
            n = request('/api/nodes', body)
            join = request('/api/nodes/' + n['id'] + '/join', {'master_url': 'https://panel.test', 'ttl_seconds': 3600})
            # Consume actual shortcut role flags, not a hand-constructed enrollment request.
            words = shlex.split(join['command'])
            flags = words[words.index('veilink:latest') + 1:]
            command('docker', 'run', '-itd', '--name', names[role], '--network', network, '--network-alias', role,
                    '--restart', 'unless-stopped', '-e', 'TZ=Asia/Shanghai', '-v', str(certs / 'ca.pem') + ':/config/ca.pem:ro',
                    a.image, *flags, '-control-ca', '/config/ca.pem')
            created.append(names[role])
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            nodes = request('/api/nodes')
            if len(nodes) == 2 and all(n['last_seen'] and n['desired_revision'] == n['applied_revision'] and not n['error'] for n in nodes):
                break
            time.sleep(2)
        else:
            raise RuntimeError('gRPC enrollment/heartbeat/application through nginx timed out')
        before = {n['id']: n['last_seen'] for n in nodes}
        time.sleep(12)
        nodes = request('/api/nodes')
        assert all(n['last_seen'] > before[n['id']] for n in nodes)
        result.update(passed=True, tls_verification=True, untrusted_ca_rejected=True, cookie_flags=True,
                      cross_origin_rejected=True, csrf_required=True, web=True, shortcut_enrollment=True,
                      h2c_heartbeat_advanced=True, nodes=[{k: n[k] for k in ('role', 'desired_revision', 'applied_revision')} for n in nodes])
    except Exception as e:
        result['error'] = str(e)
        raise
    finally:
        for role in ('nginx', 'master', 'server', 'client'):
            if names[role] in created:
                logs = command('docker', 'logs', '--tail', '100', names[role], check=False)
                (a.output / (role + '.log')).write_bytes(logs.stdout + logs.stderr)
        for name in reversed(created):
            command('docker', 'rm', '-f', name, check=False)
        command('docker', 'network', 'rm', network, check=False)
        result['cleanup_remaining'] = command('docker', 'ps', '-aq', '--filter', 'name=' + prefix, check=False).stdout.decode().strip()
        (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
