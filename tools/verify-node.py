#!/usr/bin/env python3
"""Verify a running container against an independently trusted binary SHA-256.
Requires trusted Docker administration access; this is not remote attestation.
Never derive expected_sha256 from the node being verified.
"""
import argparse
import hashlib
import json
import re
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path


def docker_bytes(container, *args):
    p = subprocess.run(['docker', 'exec', container, *args], capture_output=True, timeout=30)
    if p.returncode:
        raise RuntimeError('Docker inspection failed (container must be running)')
    return p.stdout


def evaluate(expected, actual, node):
    checks = {
        'binary_sha256': actual['sha256'] == expected['sha256'],
        'process_node_id': actual['node_id'] == expected['node_id'],
        'process_role': actual['role'] == node.get('role') and actual['role'] in ('server', 'client'),
        'binary_version': actual['version_output'] == 'veilink %s (%s)' % (expected['version'], expected['commit']),
        'reported_version': node.get('software_version') == expected['version'],
        'reported_commit': node.get('software_commit') == expected['commit'],
        'api_node_id': node.get('id') == expected['node_id'],
        'not_revoked': node.get('revoked') is False,
    }
    return {'verified': all(checks.values()), 'checks': checks, 'expected': expected, 'observed': actual,
            'reported': {k: node.get(k) for k in ('id', 'role', 'software_version', 'software_commit', 'last_seen')},
            'trust_boundary': 'Trusted Docker daemon/host and independently trusted expected binary digest; not remote attestation. Point-in-time only.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container', required=True)
    parser.add_argument('--node-id', required=True)
    parser.add_argument('--expected-sha256', required=True, help='digest from independently trusted extracted platform binary, NOT archive digest')
    parser.add_argument('--expected-version', required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--master-url', required=True, help='HTTPS origin; HTTP permitted only for loopback inspection')
    parser.add_argument('--master-container', help='read API over trusted Docker exec; URL must be container loopback HTTP')
    parser.add_argument('--session-file', type=Path, required=True, help='private file containing existing veilink_session cookie value')
    parser.add_argument('--ca', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9a-f]{64}', args.expected_sha256):
        parser.error('expected-sha256 must be 64 lowercase hexadecimal characters')
    origin = urllib.parse.urlsplit(args.master_url)
    if origin.username or origin.password or origin.query or origin.fragment or origin.path not in ('', '/'):
        parser.error('master-url must be an origin')
    if origin.scheme != 'https' and not (origin.scheme == 'http' and origin.hostname in ('127.0.0.1', '::1', 'localhost')):
        parser.error('TLS required except loopback')
    if args.master_container and not (origin.scheme == 'http' and origin.hostname in ('127.0.0.1', '::1', 'localhost')):
        parser.error('master-container requires loopback HTTP')
    if args.session_file.stat().st_mode & 0o077:
        parser.error('session-file must not be accessible by group/others (chmod 600)')
    session = args.session_file.read_text().strip()
    if not session or any(c.isspace() or c in ';\r\n' for c in session):
        parser.error('invalid session cookie')
    context = ssl.create_default_context(cafile=str(args.ca) if args.ca else None)
    # No proxy inheritance, redirects or credential forwarding to another origin.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *unused):
            raise RuntimeError('redirect refused')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), NoRedirect())
    def get(path):
        if args.master_container:
            proc = subprocess.run(['docker', 'exec', '-i', args.master_container, 'curl', '--noproxy', '*', '-fsS', '--max-time', '10', '-H', '@-', args.master_url.rstrip('/') + path], input=('Cookie: veilink_session=' + session + '\n').encode(), capture_output=True, timeout=15)
            if proc.returncode:
                raise RuntimeError('Master container API request failed')
            return json.loads(proc.stdout)
        req = urllib.request.Request(args.master_url.rstrip('/') + path, headers={'Cookie': 'veilink_session=' + session})
        with opener.open(req, timeout=10) as response:
            return json.load(response)
    nodes = get('/api/nodes')
    node = next((n for n in nodes if n['id'] == args.node_id), None)
    if node is None:
        raise RuntimeError('node not found in authenticated management response')
    master = get('/api/version')
    started = docker_bytes(args.container, 'cat', '/proc/1/stat').decode().rsplit(')', 1)[1].split()[19]
    cmdline = docker_bytes(args.container, 'cat', '/proc/1/cmdline').decode().split('\0')
    node_ids = []
    for i, value in enumerate(cmdline):
        if value == '-node-id' and i + 1 < len(cmdline):
            node_ids.append(cmdline[i + 1])
        elif value.startswith('-node-id='):
            node_ids.append(value.split('=', 1)[1])
    if len(node_ids) != 1:
        raise RuntimeError('PID 1 must have exactly one node-id argument')
    # Hash on the verifier host; never accept a digest supplied by the node API.
    digest = hashlib.sha256(docker_bytes(args.container, 'cat', '/proc/1/exe')).hexdigest()
    actual = {'sha256': digest, 'node_id': node_ids[0], 'role': cmdline[1],
              'version_output': docker_bytes(args.container, '/proc/1/exe', 'version').decode().strip()}
    expected = {'sha256': args.expected_sha256, 'node_id': args.node_id,
                'version': args.expected_version, 'commit': args.expected_commit}
    report = evaluate(expected, actual, node)
    report['master'] = master  # Informational; different node and Master builds are not automatically invalid.
    report['container'] = args.container
    # Ensure PID 1 identity did not change during measurement.
    after = docker_bytes(args.container, 'cat', '/proc/1/cmdline').decode().split('\0')
    ended = docker_bytes(args.container, 'cat', '/proc/1/stat').decode().rsplit(')', 1)[1].split()[19]
    second_digest = hashlib.sha256(docker_bytes(args.container, 'cat', '/proc/1/exe')).hexdigest()
    report['checks']['process_stable'] = after == cmdline and started == ended and digest == second_digest
    report['verified'] = all(report['checks'].values())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as out:
        json.dump(report, out, indent=2)
        out.write('\n')
    print(json.dumps({'verified': report['verified'], 'checks': report['checks'], 'output': str(args.output)}, indent=2))
    return 0 if report['verified'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        print('Verification failed: ' + str(e), file=sys.stderr)
        sys.exit(2)
