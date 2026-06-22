---
description: This article explains the security of the features of the SecretManagement and SecretStore modules.
ms.date: 06/28/2023
title: Understanding the security features of SecretManagement and SecretStore
---
# Understanding the security features of SecretManagement and SecretStore

The security of **SecretManagement** is dependent on the extension vaults it hosts. These vaults
perform the actual functions of storing and retrieving the secrets. **SecretManagement** does not
return secrets as plain text by default. By default, any text secrets are returned as
**SecureString** objects unless the user explicitly requests the secret as plain text using the
**AsPlaintext** switch.

It is critical that you only use extension vault modules published by known and trusted sources, and
that have valid package signatures.

The **SecretStore** extension vault uses .NET cryptography APIs to encrypt secret data and store it
on the local file system. The store configuration information and secret metadata are also stored in
encrypted form to prevent inadvertent disclosure or casual reading.

The secret storage file is validated by a cryptographic hash to detect file corruption or tampering.
All of this information is protected by a single cryptographic key and optional password.

The default configuration of **SecretStore** requires a password. However a password is more
difficult to manage since it must be provided when first configuring the **SecretStore** vault, and
provided again when accessing the store.

For the best security, use a password that is not stored on the local machine so it cannot be
discovered if the machine is ever breached.

The **SecretStore** configuration includes a **PasswordTimeout**, which limits the amount of time
that the vault remains unlocked during a session.

A timeout value of `-1` means that the vault remains unlocked for the entire life of the session.
This is potentially less secure, but is useful when running an unattended script in a single
session. The vault is unlocked, using `Unlock-SecretStore`, and remains unlocked for the entire
session. The session is closed when the script completes.

The password authentication requirement can also be turned off completely. In this case no password
is required to access secrets from a logged in account, and is much more convenient. The secrets are
still encrypted, but the key to decrypt the secrets is stored on the file system for the current
user account. The key is protected only by the OS file system security. The key could be discovered
by other accounts that have read privileges on files owned by that user account. Therefore, the
no-password configuration is not recommended for any systems needing strong security protections of
the stored secrets.
