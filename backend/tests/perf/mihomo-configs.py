import hashlib, json, pathlib, ssl, sys
D = pathlib.Path(sys.argv[1]).resolve()
variant = sys.argv[2] if len(sys.argv) > 2 else 'standard'
cc = {'up': '0', 'down': '0', 'cwnd': 32, 'bbr-profile': 'standard'}
if variant == 'cwnd128': cc['cwnd'] = 128
if variant == 'mtu1400': cc['udp-mtu'] = 1400
if variant == 'windows':
    cc.update({'initial-stream-receive-window': 16777216, 'max-stream-receive-window': 33554432, 'initial-connection-receive-window': 33554432, 'max-connection-receive-window': 67108864})
base = {'mode': 'rule', 'log-level': 'warning', 'ipv6': False, 'profile': {'store-selected': False}, 'dns': {'enable': False}}
server = dict(base, listeners=[dict(cc, name='hy2-in', type='hysteria2', listen='127.0.0.1', port=19444, users={'bench': 'perf-local-auth'}, certificate=str(D/'server/cert.pem'), **{'private-key': str(D/'server/key.pem'), 'ignore-client-bandwidth': True})], rules=['IP-CIDR,127.0.0.1/32,DIRECT,no-resolve', 'MATCH,REJECT'])
client = dict(base, listeners=[{'name': 'forward', 'type': 'tunnel', 'listen': '127.0.0.1', 'port': 19080, 'network': ['tcp', 'udp'], 'target': '127.0.0.1:19443', 'proxy': 'hy2'}], proxies=[dict(cc, name='hy2', type='hysteria2', server='127.0.0.1', port=19444, password='perf-local-auth', sni='gateway.test', fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert((D/'cert.pem').read_text())).hexdigest())], rules=['MATCH,hy2'])
for name, obj in [('server', server), ('client', client)]:
    (D / ('mihomo-'+name+'.json')).write_text(json.dumps(obj, indent=2))
