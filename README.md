# sasl-xoauth2-gnome-online-accounts

`Sasl-xoauth2-gnome-online-accounts` is a [Cyrus SASL] client plugin that
implements the [XOAUTH2] mechanism via dbus calls to GNOME Online Accounts.

## Installation

```
cargo build --release
install -m0755 target/release/libsasl_xoauth2_gnome_online_accounts.so /usr/lib64/sasl2
```

The library can be installed in alternative locations if `SASL_PATH` is
set/configured correctly.

## `mbsync`

If using `mbsync`, select the mechanism:

```
AuthMechs XOAUTH2
```

[Cyrus SASL]: https://www.cyrusimap.org/sasl/
[XOAUTH2]: https://developers.google.com/workspace/gmail/imap/xoauth2-protocol
