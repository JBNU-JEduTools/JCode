# HAProxy certificate renewal

Only the HAProxy main node requests the `jedutools.io` wildcard certificate.
Certbot uses a Cloudflare token stored outside Git at
`/etc/letsencrypt/cloudflare.ini`. Its deploy hook runs
`deploy-jedutools-cert`, which validates the certificate/key pair, installs and
reloads the backup node first, then installs and reloads the main node.
The daily `jedutools-cert-sync.timer` retries synchronization if the backup was
temporarily unavailable when Certbot renewed the certificate. Unchanged
certificates do not trigger an HAProxy reload.

The main node's `/root/.ssh/jedutools-cert-sync` key is restricted on the backup
node to the root-owned `install-jedutools-cert` command. The Cloudflare token
must retain Zone DNS edit and zone read access for automated renewal to work.

Validate the installed state with:

```bash
certbot certificates --cert-name jedutools.io
systemctl status certbot.timer
systemctl status jedutools-cert-sync.timer
openssl x509 -in /etc/ssl/jedutools/haproxy-combined.pem -noout -dates -ext subjectAltName
```

Both timers run on the main HAProxy node. The backup node only contains the
root-owned receiver and a forced-command SSH public key; it does not contain
the Cloudflare token or synchronization private key.
