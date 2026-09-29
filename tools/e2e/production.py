#!/usr/bin/env python3
"""Production configuration and persistence smoke test against a disposable DB.

Requires RIVET_TEST_DATABASE_URL. Never point it at a real deployment database.
Logs and receipts omit tokens, signing seeds and database connection strings.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]


def main():
    database = os.environ['RIVET_TEST_DATABASE_URL']
    evidence = Path(os.environ.get('RIVET_PRODUCTION_EVIDENCE', tempfile.mkdtemp(prefix='rivet-production-results-')))
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='rivet-production-') as folder:
        base = Path(folder)
        binary = base / 'registry'
        subprocess.run(['go', 'build', '-o', str(binary), './cmd/server'], cwd=ROOT / 'registry', check=True)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        url = f'http://127.0.0.1:{port}'
        key = base / 'signing.key'
        key.write_text(base64.b64encode(secrets.token_bytes(32)).decode() + '\n')
        key.chmod(0o600)
        token = secrets.token_hex(32)
        env = dict(os.environ, RIVET_ENV='production', RIVET_STORE='postgres', DATABASE_URL=database,
                   RIVET_DATA_DIR=str(base / 'data'), RIVET_SIGNING_KEY='', RIVET_SIGNING_KEY_FILE=str(key),
                   RIVET_REGISTRY_TOKEN=token, RIVET_ADMIN_TOKEN=secrets.token_hex(32),
                   RIVET_PUBLIC_MIRROR='false', RIVET_AUDIT_MODE='static', RIVET_ADDR=f'127.0.0.1:{port}')
        for label, change, expected in (
            ('memory', {'RIVET_STORE': 'memory'}, 'not allowed in production'),
            ('missing-key', {'RIVET_SIGNING_KEY_FILE': str(base / 'absent')}, 'load signing key'),
            ('short-token', {'RIVET_REGISTRY_TOKEN': 'short'}, 'at least 32 characters'),
        ):
            result = subprocess.run([str(binary)], env=dict(env, **change), text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
            assert result.returncode != 0 and expected in result.stdout, f'{label}: wrong startup behavior'

        def request(path, data=None, authorized=False):
            headers = {'Content-Type': 'application/json'}
            if authorized:
                headers['Authorization'] = 'Bearer ' + token
            req = Request(url + path, data=json.dumps(data).encode() if data is not None else None, headers=headers)
            with urlopen(req, timeout=180) as response:
                return response.read()

        process = None
        log = (evidence / 'production.log').open('w')

        def stop():
            nonlocal process
            if process:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                process = None

        def start():
            nonlocal process
            process = subprocess.Popen([str(binary)], env=env, stdout=log, stderr=subprocess.STDOUT)
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError('production registry exited during startup')
                try:
                    request('/healthz')
                    return
                except OSError:
                    time.sleep(.1)
            raise AssertionError('production registry failed readiness')

        try:
            start()
            public_key = request('/v1/keys')
            payload = {'name': 'semver', 'version': '7.7.1'}
            try:
                request('/v1/import/npm', payload)
            except HTTPError as error:
                assert error.code == 401
            else:
                raise AssertionError('unauthenticated import succeeded')
            request('/v1/import/npm', payload, authorized=True)
            envelope = json.loads(request('/v1/packages/semver/7.7.1/attestation'))
            statement = json.loads(base64.b64decode(envelope['payload']))
            # Capture the actual artifact bytes before restarting the server.
            artifact_hash = statement['artifact']['hash']
            artifact = request('/v1/artifacts/' + artifact_hash)
            assert hashlib.sha512(artifact).hexdigest() == artifact_hash.removeprefix('sha512-')
            stop()
            start()
            assert request('/v1/keys') == public_key, 'signing identity changed across restart'
            after = json.loads(request('/v1/packages/semver/7.7.1/attestation'))
            after_statement = json.loads(base64.b64decode(after['payload']))
            assert after_statement['artifact']['hash'] == artifact_hash, 'database release changed or disappeared'
            assert request('/v1/artifacts/' + artifact_hash) == artifact, 'artifact persistence failed'
            (evidence / 'production.json').write_text(json.dumps({
                'status': 'passed', 'mode': 'production', 'audit_mode': 'static',
                'startup_refusals': ['memory', 'missing-key', 'short-token'],
                'unauthenticated_import': 'refused', 'restart_key_and_release_and_artifact': 'preserved',
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
            }, indent=2) + '\n')
            print('PASS production startup, authentication, and restart persistence')
        finally:
            stop()
            log.close()


if __name__ == '__main__':
    main()
