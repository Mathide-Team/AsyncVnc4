"""SASL contre un vrai serveur : le VNC intégré de QEMU (issue #32).

QEMU (ui/vnc-auth-sasl.c) ne propose PLAIN que dans le sous-type VeNCrypt
X509SASL (TLS avec certificat, 263). En SASL seul (type 20) ou en TLSSASL
(TLS anonyme, 264), il exige un mécanisme qui chiffre lui-même (min_ssf=56,
NOPLAINTEXT, NOANONYMOUS) : PLAIN disparaît de la liste. Les tests couvrent
les deux côtés : le chemin qui marche et les refus explicites.

Requiert `qemu-system-x86_64`, `saslpasswd2` (sasl2-bin), le module Cyrus
PLAIN et sasldb (libsasl2-modules) et `openssl`. Sans eux, la suite est
sautée, sauf si `ASYNCVNC_LIVE=1`.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest

import asyncvnc2

OUTILS = all(shutil.which(o) for o in ('qemu-system-x86_64', 'saslpasswd2', 'openssl'))
EXIGE = os.environ.get('ASYNCVNC_LIVE') == '1'
UTILISATEUR, MOT_DE_PASSE = 'alice', 'secret12'


def _port_libre() -> int:
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _openssl(*args: str) -> None:
    subprocess.run(['openssl', *args], check=True, capture_output=True)


@unittest.skipUnless(
    OUTILS or EXIGE, 'QEMU/sasl2-bin/openssl absents (ASYNCVNC_LIVE=1 pour exiger)'
)
class TestQemuSasl(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not OUTILS:
            raise AssertionError(
                'ASYNCVNC_LIVE=1 mais qemu-system-x86_64, saslpasswd2 ou openssl est absent'
            )
        cls.tmp = tempfile.TemporaryDirectory()
        d = cls.tmp.name
        cls.sasldb = os.path.join(d, 'passwd.db')
        subprocess.run(
            ['saslpasswd2', '-p', '-a', 'qemu', '-f', cls.sasldb, '-c', UTILISATEUR],
            input=MOT_DE_PASSE.encode(),
            check=True,
            capture_output=True,
        )
        # PKI : CA (keyUsage exigé par Python >= 3.13) + certificat serveur 127.0.0.1.
        cls.pki = os.path.join(d, 'pki')
        os.mkdir(cls.pki)
        p = cls.pki
        _openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', f'{p}/ca-key.pem',
                 '-out', f'{p}/ca-cert.pem', '-days', '2', '-subj', '/CN=Test CA',
                 '-addext', 'basicConstraints=critical,CA:TRUE',
                 '-addext', 'keyUsage=critical,keyCertSign,cRLSign')  # fmt: skip
        _openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', f'{p}/server-key.pem',
                 '-out', f'{p}/server.csr', '-subj', '/CN=127.0.0.1')  # fmt: skip
        with open(f'{p}/ext.cnf', 'w', encoding='ascii') as f:
            f.write(
                'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n'
                'keyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=CA:FALSE\n'
            )
        _openssl('x509', '-req', '-in', f'{p}/server.csr', '-CA', f'{p}/ca-cert.pem',
                 '-CAkey', f'{p}/ca-key.pem', '-CAcreateserial', '-out', f'{p}/server-cert.pem',
                 '-days', '2', '-extfile', f'{p}/ext.cnf')  # fmt: skip
        # TLS anonyme : sans dh-params.pem, GnuTLS 3.8 refuse la poignée de
        # main (« Insufficient credentials ») ; groupe RFC 7919 instantané.
        cls.anon = os.path.join(d, 'anon')
        os.mkdir(cls.anon)
        _openssl('genpkey', '-genparam', '-algorithm', 'DH', '-pkeyopt', 'group:ffdhe2048',
                 '-out', f'{cls.anon}/dh-params.pem')  # fmt: skip
        cls.qemus: list[subprocess.Popen] = []

    @classmethod
    def tearDownClass(cls):
        for q in cls.qemus:
            q.terminate()
            try:
                q.wait(5)
            except subprocess.TimeoutExpired:
                q.kill()
        cls.tmp.cleanup()

    def _qemu(self, mechs: str, tls: str | None) -> int:
        conf = tempfile.mkdtemp(dir=self.tmp.name)
        with open(os.path.join(conf, 'qemu.conf'), 'w', encoding='ascii') as f:
            f.write(f'mech_list: {mechs}\nsasldb_path: {self.sasldb}\n')
        port = _port_libre()
        vnc = f'127.0.0.1:{port - 5900},sasl=on'
        args = []
        if tls == 'x509':
            args = [
                '-object',
                f'tls-creds-x509,id=tls0,dir={self.pki},endpoint=server,verify-peer=off',
            ]
            vnc += ',tls-creds=tls0'
        elif tls == 'anon':
            args = ['-object', f'tls-creds-anon,id=tls0,dir={self.anon},endpoint=server']
            vnc += ',tls-creds=tls0'
        q = subprocess.Popen(
            ['qemu-system-x86_64', '-display', 'none', '-nodefaults', '-vga', 'std', '-m', '32',
             *args, '-vnc', vnc],
            env={**os.environ, 'SASL_CONF_PATH': conf},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )  # fmt: skip
        self.qemus.append(q)
        fin = time.monotonic() + 15
        while time.monotonic() < fin:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                    return port
            except OSError:
                time.sleep(0.2)
        raise TimeoutError('QEMU ne répond pas')

    def _connect(self, port: int, user: str, pw: str, ca: bool = True):
        ctx = ssl.create_default_context(cafile=f'{self.pki}/ca-cert.pem') if ca else None

        async def scenario():
            async with asyncvnc2.connect(
                '127.0.0.1', port, username=user, password=pw, ssl_context=ctx
            ) as client:
                image = await asyncio.wait_for(client.screenshot(), 20)
                return client.protocol_version, image.shape

        return asyncio.run(asyncio.wait_for(scenario(), 30))

    def test_x509sasl_plain(self):
        port = self._qemu('plain', 'x509')
        version, forme = self._connect(port, UTILISATEUR, MOT_DE_PASSE)
        self.assertEqual(version, (3, 8))
        self.assertEqual(forme[2], 4)
        self.assertGreater(forme[0] * forme[1], 0)

    def test_x509sasl_mauvais_mot_de_passe(self):
        port = self._qemu('plain', 'x509')
        with self.assertRaises(PermissionError):
            self._connect(port, UTILISATEUR, 'mauvais1')

    def test_x509sasl_utilisateur_inconnu(self):
        port = self._qemu('plain', 'x509')
        with self.assertRaises(PermissionError):
            self._connect(port, 'bob', MOT_DE_PASSE)

    def test_x509sasl_certificat_non_reconnu(self):
        port = self._qemu('plain', 'x509')
        with self.assertRaises(ssl.SSLCertVerificationError):
            self._connect(port, UTILISATEUR, MOT_DE_PASSE, ca=False)

    def test_sasl_sans_tls_plain_retire(self):
        port = self._qemu('plain', None)
        with self.assertRaises(ConnectionError) as ctx:
            self._connect(port, UTILISATEUR, MOT_DE_PASSE, ca=False)
        self.assertIn('X509SASL', str(ctx.exception))

    def test_sasl_sans_tls_seulement_digest_md5(self):
        port = self._qemu('digest-md5 plain', None)
        with self.assertRaises(ValueError) as ctx:
            self._connect(port, UTILISATEUR, MOT_DE_PASSE, ca=False)
        self.assertIn('DIGEST-MD5', str(ctx.exception))

    def test_tlssasl_anonyme_plain_retire(self):
        port = self._qemu('plain', 'anon')
        with self.assertRaises(ConnectionError):
            self._connect(port, UTILISATEUR, MOT_DE_PASSE, ca=False)


if __name__ == '__main__':
    unittest.main()
