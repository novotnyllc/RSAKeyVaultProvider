using Microsoft.Azure.KeyVault;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.WebKey;
using System.Security.Cryptography;

namespace RSAKeyVaultProviderTests
{
    internal static class KeyVaultConfigurationDiscoverer
    {
        public static async Task<AzureKeyVaultMaterializedConfiguration> Materialize(AzureKeyVaultSignConfigurationSet configuration)
        {
            async Task<string> Authenticate(string authority, string resource, string scope)
            {
                if (!string.IsNullOrWhiteSpace(configuration.AzureAccessToken))
                {
                    return configuration.AzureAccessToken;
                }

                var context = new AuthenticationContext(authority);
                ClientCredential credential = new ClientCredential(configuration.AzureClientId, configuration.AzureClientSecret);

                AuthenticationResult result = await context.AcquireTokenAsync(resource, credential).ConfigureAwait(false);
                if (result == null)
                {
                    throw new InvalidOperationException("Authentication to Azure failed.");
                }
                return result.AccessToken;
            }
            var client = new HttpClient();
            var vault = new KeyVaultClient(Authenticate, client);
            if (configuration.Mode == KeyVaultMode.Certificate)
            {
                var azureCertificate = await vault.GetCertificateAsync(configuration.AzureKeyVaultUrl, configuration.AzureKeyVaultKeyName).ConfigureAwait(false);
                var x509Certificate = new X509Certificate2(azureCertificate.Cer);
                var keyId = azureCertificate.KeyIdentifier;
                
                return new AzureKeyVaultMaterializedConfiguration(vault, keyId, publicCertificate: x509Certificate);
            }
            else if(configuration.Mode == KeyVaultMode.Key)
            {
                var bundle = await vault.GetKeyAsync(configuration.AzureKeyVaultUrl, configuration.AzureKeyVaultKeyName).ConfigureAwait(false);
                return new AzureKeyVaultMaterializedConfiguration(vault, bundle.KeyIdentifier, bundle.Key);
            }
            throw new ArgumentOutOfRangeException(nameof(configuration));
        }
    }

    public class AzureKeyVaultMaterializedConfiguration : IDisposable
    {
        public AzureKeyVaultMaterializedConfiguration(KeyVaultClient client, 
                                                      KeyIdentifier keyIdentifier, 
                                                      JsonWebKey key = null,
                                                      X509Certificate2 publicCertificate = null)
        {
            
            
            PublicCertificate = publicCertificate;
            Client = client ?? throw new ArgumentNullException(nameof(client));
            KeyIdentifier = keyIdentifier ?? throw new ArgumentNullException(nameof(keyIdentifier));
            if(publicCertificate == null && key == null)
                throw new ArgumentNullException(nameof(key), "Either key or publicCertificate must be set");

            Key = key;
        }
        
        /// <summary>
        /// Can be null if Key isn't part of an x509 certificate
        /// </summary>
        public X509Certificate2 PublicCertificate { get; }
        public KeyVaultClient Client { get; }
        public KeyIdentifier KeyIdentifier { get; }
        /// <summary>
        /// Only contains the public key
        /// </summary>
        public JsonWebKey Key { get; }

        public void Dispose()
        {
            Client.Dispose();
        }

        public RSAKeyVault ToRSA()
        {
            if (PublicCertificate != null)
                return (RSAKeyVault)Client.ToRSA(KeyIdentifier, PublicCertificate);
            return (RSAKeyVault)Client.ToRSA(KeyIdentifier, Key);
        }
    }
}
