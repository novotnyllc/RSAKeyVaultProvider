# About
The `RSAKeyVaultProvider` enables you to use secrets and certificates stored in an 
Azure Key Vault for performing signing and decryption operations. (Encrypt and verify
can be done locally with the public key material.) The type derives from `RSA` so can
be used anywhere an `AsymmetricAlgorithm` can be, including with `SignedXml` types.

## Package
NuGet: `RSAKeyVaultProvider`<br />
[![RSAKeyVaultProvider](https://img.shields.io/nuget/v/RSAKeyVaultProvider.svg)](https://www.nuget.org/packages/RSAKeyVaultProvider)

CI feed is on Azure Artifacts:
`https://pkgs.dev.azure.com/clairernovotny/GitBuilds/_packaging/RSAKeyVaultProvider/nuget/v3/index.json` <br />
[![RSAKeyVaultProvider package in RSAKeyVaultProvider feed in Azure Artifacts](https://feeds.dev.azure.com/clairernovotny/96789f1c-e804-4671-be78-d063a4eced9b/_apis/public/Packaging/Feeds/4e903115-b002-444a-9696-85e1faf90bf8/Packages/dd0c51ea-6eeb-4872-a9dc-9083718d61d1/Badge)](https://dev.azure.com/onovotny/GitBuilds/_packaging?_a=package&feed=4e903115-b002-444a-9696-85e1faf90bf8&package=dd0c51ea-6eeb-4872-a9dc-9083718d61d1&preferRelease=true)

## Setup
To run these tests, you'll need to import a code signing certificate into an
Azure Key Vault. You can do this by importing the PFX for certs you already have,
or, the harder way, by generating a CSR in the HSM and using that for an EV Code
Signing certificate. You will also need to create a new RSA key using `Add-AzureKeyVaultKey` or
the UI mentioned below. Use the key name as the `azureKeyVaultKeyName` in the 
config and the certificate name as the `azureKeyVaultCertificateName`.

You can also use the Azure Portal to generate a new key and certificate. In the cetificate make sure
to go to the advanced policies and select "Data Encipherment" so that it can do the decrypt tests.

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
  "tenantId": "",
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
