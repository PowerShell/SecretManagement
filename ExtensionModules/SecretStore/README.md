# PowerShell Secret Store module

This module is an extension vault module for the PowerShell SecretManagement module.
It stores secrets locally in file for the current user account context.
It uses .NET crypto APIs to encrypt file contents.
This module works over all supported PowerShell platforms.
In the default configuration, a password is required to store and access secrets.

