# Systemd Unit Examples for Exim

This directory contains several examples for Systemd units to manage an Exim installation.
There is room for improvement, so please share your ideas or setups that are proven to work
in your environment.

All the service units try to protect the system from unintentional
writes to locations outside of Exim's spool, and log directories.  You
may need to override specific settings, we recommend using Systemd's
override mechanism (`systemd edit …`).

The .service units use `ProtectSystem=strict`, which implies a read-only
file system structure. Exim needs write access to the spool directory
(main config option: `spool_directory`), and the log directory (main
config option: `log_file_path`). For improved security you can even set
`NoNewPrivileges`, if you don't do local deliveries.

The provided Systemd units are examples, containing placeholders
`{{…}}`. The [install script](./install) helps substituting them.
The following placeholders are used currently:
- `exim`:
- `spooldir:`
- `logdir`:


## Daemon

This is best suited for *average to high traffic systems*, it engages
all built-in Exim facilities, as queue runner management and system load
depending message processing.

The [systemd service unit](./daemon/exim.service) starts the Exim main
process. This process listens on the ports configured in the _runtime
configuration_ (typically `exim.conf`), and supervises all other
activities, including management of queue runner startups. Basically it
calls `exim -odf -q...`.

For regular maintenance tasks (database cleanup) additional units are
[required](./maintenance).

## Socket

This is best suited for *low traffic* systems, which experience a
message *burst* from time to time. Regular desktop, and edge systems fit this
pattern.

Exim's start is delayed until the first connection. Once a connection is
initiated, Exim starts a listener on the port configured in the [systemd
socket unit](./socket/exim.socket) and waits for more connections. It
exits after being idle for a while. Basically it calls `exim -bw ...`.

Additional [_queue runner_ timer and service units](#queue-runner) are required.

For regular maintenance tasks (database cleanup)
additional units are [required](./maintenance).

## Inetd

This is best suited for systems with *low traffic*, if the
[socket](#socket) approach doesn't work.

For each incoming connection a new Exim instance starts, handling
exactly this connection and then exits. The listener port is configured
in the [systemd socket unit](./inetd/exim.socket).

Additional [_queue runner_ timer and service units](#queue-runner) are required.

For regular maintenance tasks (database cleanup)
additional units are [required](./maintenance).

## Queue Runner

This is a *timer*, and a *service* unit which starts Exim queue runner
processes. This is necessary, as the socket activated Exim instances
(from [socket](#socket) and [inetd](#inetd) do not care, once the first
delivery attempt is done.

## Maintenance

This is a *timer* unit, and a *service* unit for regular maintenance
tasks.  For security it is recommended to use the `User=` Systemd
directive in a local override file.

The service unit cares about tidying Exim's hint databases. It *does
not* rotate the log files, as most systems have their own mechanism for
doing this job (e.g. Logrotate).
