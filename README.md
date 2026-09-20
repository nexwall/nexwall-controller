# Nexwall Central Management

Server side of Nexwall Firewall: a set of services that lets an administrator manage many firewalls from one place.

Firewalls register with the server using the `ns-plug` client. On registration the server:

- creates a VPN configuration and sends it back to the firewall
- creates a route inside the proxy to reach the firewall management API
- stores the credentials needed to access the remote firewall

| Directory | Content |
|---|---|
| `api` | management API (Go) |
| `proxy` | proxy to reach registered firewalls |
| `vpn` | VPN server |
| `ui` | web interface |
| `test` | tests |

## License

GPL-3.0, see `LICENSE`. Attribution and the list of changes are in `NOTICE.md`.
