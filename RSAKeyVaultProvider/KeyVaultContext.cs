using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.WebKey;

namespace Microsoft.Azure.KeyVault
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
        public KeyVaultContext(KeyVaultClient client, KeyIdentifier keyIdentifier, JsonWebKey key)
        {
            this.client = client ?? throw new ArgumentNullException(nameof(client));
            KeyIdentifier = keyIdentifier ?? throw new ArgumentNullException(nameof(keyIdentifier));
            Key = key ?? throw new ArgumentNullException(nameof(key));
            Certificate = null;
        }
        
        /// <summary>
        /// Creates a new Key Vault context.
        /// </summary>
        public KeyVaultContext(KeyVaultClient client, KeyIdentifier keyIdentifier, X509Certificate2 publicCertificate)
        {
            Certificate = publicCertificate ?? throw new ArgumentNullException(nameof(publicCertificate));
            this.client = client ?? throw new ArgumentNullException(nameof(client));
            KeyIdentifier = keyIdentifier ?? throw new ArgumentNullException(nameof(keyIdentifier));
            using (var rsa = publicCertificate.GetRSAPublicKey())
            {
                Key = new JsonWebKey(rsa.ExportParameters(false));
            }
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

        internal async Task<byte[]> SignDigestAsync(byte[] digest, HashAlgorithmName hashAlgorithm)
        {
            var algorithm = SignatureAlgorithmTranslator.SignatureAlgorithmToJwsAlgId(hashAlgorithm);

            if (hashAlgorithm == HashAlgorithmName.SHA1)
                digest = CreateSHA1Digest(digest);

            var signature = await client.SignAsync(KeyIdentifier.Identifier, algorithm, digest).ConfigureAwait(false);
            return signature.Result;
        }

        internal async Task<byte[]> DecryptDataAsync(byte[] cipherText, RSAEncryptionPadding padding)
        {
            var algorithm = EncryptionPaddingTranslator.EncryptionPaddingToJwsAlgId(padding);
            var data = await client.DecryptAsync(KeyIdentifier.Identifier, algorithm, cipherText).ConfigureAwait(false);
            return data.Result;
        }

        private static byte[] CreateSHA1Digest(byte[] digest)
        {
            var hashAlgorithm = SHA1.Create();
            byte[] hash = hashAlgorithm.ComputeHash(digest);

            if (hash == null || hash.Length == 0)
                throw new ArgumentNullException(nameof(hash));

            byte[] newPkcs1Digest = null;

            if (hash.Length != 20)
                throw new ArgumentException("Invalid hash value");

            newPkcs1Digest = new byte[] { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            Array.Copy(hash, 0, newPkcs1Digest, newPkcs1Digest.Length - hash.Length, hash.Length);

            return newPkcs1Digest;
        }

        /// <summary>
        /// Returns true if properly constructed. If default, then false.
        /// </summary>
        public bool IsValid => client != null;
    }
}
