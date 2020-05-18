using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;

using RSAKeyVaultProvider;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace RSAKeyVaultProviderTests
{
    internal static class KeyVaultConfigurationDiscoverer
    {
        public static async Task<AzureKeyVaultMaterializedConfiguration> Materialize(AzureKeyVaultSignConfigurationSet configuration)
        {   
            TokenCredential credential = configuration.ManagedIdentity switch
            {
                true => new DefaultAzureCredential(),
                false => new ClientSecretCredential(configuration.AzureTenantId, configuration.AzureClientId, configuration.AzureClientSecret)
            };

            if (configuration.Mode == KeyVaultMode.Certificate)
            {
                var certificateClient = new CertificateClient(configuration.AzureKeyVaultUrl, credential);
                var cert = await certificateClient.GetCertificateAsync(configuration.AzureKeyVaultKeyName).ConfigureAwait(false);
                
                var x509Certificate = new X509Certificate2(cert.Value.Cer);                               
                var keyId = cert.Value.KeyId;
                
                return new AzureKeyVaultMaterializedConfiguration(credential, keyId, publicCertificate: x509Certificate);
            }
            else if(configuration.Mode == KeyVaultMode.Key)
            {
                var keyClient = new KeyClient(configuration.AzureKeyVaultUrl, credential);
                var key = await keyClient.GetKeyAsync(configuration.AzureKeyVaultKeyName).ConfigureAwait(false);
                return new AzureKeyVaultMaterializedConfiguration(credential, key.Value.Id, key.Value.Key);
            }
            throw new ArgumentOutOfRangeException(nameof(configuration));
        }
    }

    public class AzureKeyVaultMaterializedConfiguration 
    {
        public AzureKeyVaultMaterializedConfiguration(TokenCredential credential, 
                                                      Uri keyIdentifier, 
                                                      JsonWebKey key = null,
                                                      X509Certificate2 publicCertificate = null)
        {
            
            
            PublicCertificate = publicCertificate;
            TokenCredential = credential ?? throw new ArgumentNullException(nameof(credential));
            KeyIdentifier = keyIdentifier ?? throw new ArgumentNullException(nameof(keyIdentifier));
            if(publicCertificate == null && key == null)
                throw new ArgumentNullException(nameof(key), "Either key or publicCertificate must be set");

            Key = key;
        }
        
        /// <summary>
        /// Can be null if Key isn't part of an x509 certificate
        /// </summary>
        public X509Certificate2 PublicCertificate { get; }

        public TokenCredential TokenCredential { get; }

        public Uri KeyIdentifier { get; }
        /// <summary>
        /// Only contains the public key
        /// </summary>
        public JsonWebKey Key { get; }

        public RSAKeyVault ToRSA()
        {
            if (PublicCertificate != null)
            {
                return (RSAKeyVault)RSAFactory.Create(TokenCredential, KeyIdentifier, PublicCertificate);
            }

            return (RSAKeyVault)RSAFactory.Create(TokenCredential, KeyIdentifier, Key);
        }

        public ECDsaKeyVault ToECDsa()
        {
            if (PublicCertificate != null)
            {
                return (ECDsaKeyVault)ECDsaFactory.Create(TokenCredential, KeyIdentifier, PublicCertificate);
            }

            return (ECDsaKeyVault)ECDsaFactory.Create(TokenCredential, KeyIdentifier, Key);
        }
    }
}
