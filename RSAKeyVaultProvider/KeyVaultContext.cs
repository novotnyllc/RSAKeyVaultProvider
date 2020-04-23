using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Azure.Core;

namespace RSAKeyVaultProvider
{
    /// <summary>
    /// A signing context used for signing packages with Azure Key Vault Keys.
    /// </summary>
    public struct KeyVaultContext
    {
        readonly CryptographyClient cryptographyClient;

        /// <summary>
        /// Creates a new Key Vault context.
        /// </summary>
        public KeyVaultContext(TokenCredential credential, Uri keyId, JsonWebKey key)
        {            
            KeyIdentifier = keyId ?? throw new ArgumentNullException(nameof(keyId));
            Key = key ?? throw new ArgumentNullException(nameof(key));


            cryptographyClient = new CryptographyClient(keyId, credential);
            Certificate = null;            
        }

        /// <summary>
        /// Creates a new Key Vault context.
        /// </summary>
        public KeyVaultContext(TokenCredential credential, Uri keyId, X509Certificate2 publicCertificate)
        {
            if (credential is null)
            {
                throw new ArgumentNullException(nameof(credential));
            }

            Certificate = publicCertificate ?? throw new ArgumentNullException(nameof(publicCertificate));
            KeyIdentifier = keyId ?? throw new ArgumentNullException(nameof(keyId));

            cryptographyClient = new CryptographyClient(keyId, credential);

            using (var rsa = publicCertificate.GetRSAPublicKey())
            {
                Key = new JsonWebKey(rsa, includePrivateParameters: false);
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
        public Uri KeyIdentifier { get; }

        /// <summary>
        /// Public key 
        /// </summary>
        public JsonWebKey Key { get; }

        internal byte[] SignDigest(byte[] digest, HashAlgorithmName hashAlgorithm)
        {
            var algorithm = SignatureAlgorithmTranslator.SignatureAlgorithmToJwsAlgId(hashAlgorithm);

            if (hashAlgorithm == HashAlgorithmName.SHA1)
                digest = Sha1Helper.CreateDigest(digest);

            var sigResult = cryptographyClient.Sign(algorithm, digest);

            return sigResult.Signature;
        }

        internal byte[] DecryptData(byte[] cipherText, RSAEncryptionPadding padding)
        {
            var algorithm = EncryptionPaddingTranslator.EncryptionPaddingToJwsAlgId(padding);

            var dataResult = cryptographyClient.Decrypt(algorithm, cipherText);
            return dataResult.Plaintext;
        }

        /// <summary>
        /// Returns true if properly constructed. If default, then false.
        /// </summary>
        public bool IsValid => cryptographyClient != null;
    }
}
