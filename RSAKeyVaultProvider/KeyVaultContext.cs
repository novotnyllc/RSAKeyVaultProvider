using Microsoft.Azure.KeyVault;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.WebKey;

namespace System.Security.Cryptography
{
    /// <summary>
    /// A signing context used for signing packages with Azure Key Vault Keys.
    /// </summary>
    public struct KeyVaultContext    
    {
        readonly KeyVaultClient client;

        /// <summary>
        /// Creates a new Key Vault context.
        /// </summary>
        public KeyVaultContext(KeyVaultClient client, KeyIdentifier keyIdentifier, JsonWebKey key, SigningAlgorithm signingAlgorithm)
        {
            this.client = client ?? throw new ArgumentNullException(nameof(client));
            KeyIdentifier = keyIdentifier ?? throw new ArgumentNullException(nameof(keyIdentifier));
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Certificate = null;

            if (signingAlgorithm != SigningAlgorithm.RSA)
                throw new CryptographicException("Only RSA is supported");
            
            SignatureAlgorithm = signingAlgorithm;
        }
        
        /// <summary>
        /// Creates a new Key Vault context.
        /// </summary>
        public KeyVaultContext(KeyVaultClient client, KeyIdentifier keyIdentifier, X509Certificate2 publiCertificate, SigningAlgorithm signingAlgorithm)
        {
            Certificate = publiCertificate ?? throw new ArgumentNullException(nameof(publiCertificate));
            this.client = client ?? throw new ArgumentNullException(nameof(client));
            KeyIdentifier = keyIdentifier ?? throw new ArgumentNullException(nameof(keyIdentifier));
            using (var rsa = publiCertificate.GetRSAPublicKey())
            {
                Key = new JsonWebKey(rsa.ExportParameters(false));
            }

            if (signingAlgorithm != SigningAlgorithm.RSA)
                throw new CryptographicException("Only RSA is supported");

            SignatureAlgorithm = signingAlgorithm;
        }

        /// <summary>
        /// Gets the certificate and public key used to validate the signature. May be null if 
        /// Key isn't part of a certificate
        /// </summary>
        public X509Certificate2 Certificate { get; }
        
        /// <summary>
        /// Identifyer of current key
        /// </summary>
        public KeyIdentifier KeyIdentifier { get; }

        /// <summary>
        /// Public key 
        /// </summary>
        public JsonWebKey Key { get; }

        /// <summary>
        /// Gets the signature algorithm. Currently, only <see cref="SigningAlgorithm.RSA"/> is supported.
        /// </summary>
        public SigningAlgorithm SignatureAlgorithm { get; }

        internal async Task<byte[]> SignDigestAsync(byte[] digest, HashAlgorithmName hashAlgorithm)
        {
            var algorithm = SignatureAlgorithmTranslator.SignatureAlgorithmToJwsAlgId(SignatureAlgorithm, hashAlgorithm);
            var signature = await client.SignAsync(KeyIdentifier.Identifier, algorithm, digest).ConfigureAwait(false);
            return signature.Result;
        }

        internal async Task<byte[]> DecryptDataAsync(byte[] cipherText, RSAEncryptionPadding padding)
        {
            var algorithm = EncryptionPaddingTranslator.EncryptionPaddingToJwsAlgId(padding);
            var data = await client.DecryptAsync(KeyIdentifier.Identifier, algorithm, cipherText).ConfigureAwait(false);
            return data.Result;
        }
    }
}
