using System;
using Microsoft.Azure.KeyVault.WebKey;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Azure.KeyVault.Models;

// Namespace here so these show up in the main namespace
namespace Microsoft.Azure.KeyVault
{
    public static class RSAKeyVaultProviderExtensions
    {
        /// <summary>
        /// Creates an RSA object
        /// </summary>
        /// <param name="client"></param>
        /// <param name="keyIdentifier"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static RSA ToRSA(this KeyVaultClient client, KeyIdentifier keyIdentifier, JsonWebKey key)
        {
            if (client == null)
            {
                throw new ArgumentNullException(nameof(client));
            }

            if (keyIdentifier == null)
            {
                throw new ArgumentNullException(nameof(keyIdentifier));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            return new RSAKeyVaultProvider(new KeyVaultContext(client, keyIdentifier, key, SigningAlgorithm.RSA));
        }

        /// <summary>
        /// Creates an RSA object
        /// </summary>
        /// <param name="client"></param>
        /// <param name="keyIdentifier"></param>
        /// <param name="publicCertificate"></param>
        /// <returns></returns>
        public static RSA ToRSA(this KeyVaultClient client, KeyIdentifier keyIdentifier, X509Certificate2 publicCertificate)
        {
            if (client == null)
            {
                throw new ArgumentNullException(nameof(client));
            }

            if (keyIdentifier == null)
            {
                throw new ArgumentNullException(nameof(keyIdentifier));
            }

            if (publicCertificate == null)
            {
                throw new ArgumentNullException(nameof(publicCertificate));
            }

            return new RSAKeyVaultProvider(new KeyVaultContext(client, keyIdentifier, publicCertificate, SigningAlgorithm.RSA));
        }

        /// <summary>
        /// Creates an RSA object
        /// </summary>
        /// <param name="client"></param>
        /// <param name="keyBundle"></param>
        /// <returns></returns>
        public static RSA ToRSA(this KeyVaultClient client, KeyBundle keyBundle)
        {
            if (client == null)
            {
                throw new ArgumentNullException(nameof(client));
            }

            if (keyBundle == null)
            {
                throw new ArgumentNullException(nameof(keyBundle));
            }

            return new RSAKeyVaultProvider(new KeyVaultContext(client, keyBundle.KeyIdentifier, keyBundle.Key, SigningAlgorithm.RSA));
        }
    }
}
