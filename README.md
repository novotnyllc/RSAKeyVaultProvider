## Setup
To run these tests, you'll need to import a code signing certificate into an
Azure Key Vault. You can do this by importing the PFX for certs you already have,
or, the harder way, by generating a CSR in the HSM and using that for an EV Code
Signing certificate. You will also need to create a new RSA key using `Add-AzureKeyVaultKey` or
the UI mentioned below. Use the key name as the `azureKeyVaultKeyName` in the 
config and the certificate name as the `azureKeyVaultCertificateName`.

Create a service principal / application and grant it access to the Key Vault with the following 
permissions:

| Category | Permission |
| ----- | ---- |
| Key | Get, Sign, Decrypt |
| Certificate | Get |


You'll need to drop a json file called `azure-creds.json` in the tests `private` directory
with the following values:

```json
{
  "clientId": "",
  "clientSecret": "",
  "azureKeyVaultUrl": "",
  "azureKeyVaultCertificateName": "",
  "azureKeyVaultKeyName": "" 
}
```

## Azure Key Vault Explorer
There's a handy GUI for accessing Key Vault and includes support for importing certificates:
https://github.com/elize1979/AzureKeyVaultExplorer

The app defaults to logging into an @microsoft.com account, so if you want to connect to a 
different directory, you need to change the settings first. Change the `Authority` to `https://login.windows.net/common`
and edit the `DomainHints` value to have your AAD domain(s) in it.
