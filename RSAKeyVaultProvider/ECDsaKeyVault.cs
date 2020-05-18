using System;
using System.Security.Cryptography;

namespace RSAKeyVaultProvider
{
    /// <summary>
    /// ECDsa implementation that uses Azure Key Vault
    /// </summary>
    public sealed class ECDsaKeyVault : ECDsa
    {
        readonly KeyVaultContext context;
        ECDsa publicKey;

        /// <summary>
        /// Creates a new ECDsaKeyVault instance
        /// </summary>
        /// <param name="context">Context with parameters</param>
        public ECDsaKeyVault(KeyVaultContext context)
        {
            if (!context.IsValid)
                throw new ArgumentException("Must not be the default", nameof(context));

            this.context = context;
            publicKey = context.Key.ToECDsa();
            KeySizeValue = publicKey.KeySize;
            LegalKeySizesValue = new[] { new KeySizes(publicKey.KeySize, publicKey.KeySize, 0) };
        }

        void CheckDisposed()
        {
            if (publicKey is null)
                throw new ObjectDisposedException($"{nameof(ECDsaKeyVault)} is disposed.");
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                publicKey?.Dispose();
                publicKey = null;
            }

            base.Dispose(disposing);
        }

        public override byte[] SignHash(byte[] hash)
        {
            CheckDisposed();

            if (hash.Length == 256 / 8 && KeySize == 256)
                return context.SignDigest(hash, HashAlgorithmName.SHA256, KeyVaultSignatureAlgorithm.ECDsa);
            if (hash.Length == 384 / 8 && KeySize == 384)
                return context.SignDigest(hash, HashAlgorithmName.SHA384, KeyVaultSignatureAlgorithm.ECDsa);
            if (hash.Length == 512 / 8 && KeySize == 521) //ES512 uses nistP521
                return context.SignDigest(hash, HashAlgorithmName.SHA512, KeyVaultSignatureAlgorithm.ECDsa);

            throw new ArgumentException("Digest length is not valid for the key size.", nameof(hash));
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            IncrementalHash hash;

            try
            {
                hash = IncrementalHash.CreateHash(hashAlgorithm);
            }
            catch
            {
                throw new NotSupportedException("The specified algorithm is not supported.");
            }

            using (hash)
            {
                hash.AppendData(data, offset, count);
                return hash.GetHashAndReset();
            }
        }

        /// <inheritdoc/>
        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            CheckDisposed();

            return publicKey.VerifyHash(hash, signature);
        }

        ///<inheritdoc/>
        public override ECParameters ExportParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters)
                throw new CryptographicException("Private keys cannot be exported by this provider");

            return publicKey.ExportParameters(false);
        }

        ///<inheritdoc/>
        public override ECParameters ExportExplicitParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters)
                throw new CryptographicException("Private keys cannot be exported by this provider");

            return publicKey.ExportExplicitParameters(false);
        }

        /// <summary>
        /// Importing parameters is not supported.
        /// </summary>
        public override void ImportParameters(ECParameters parameters) =>
            throw new NotSupportedException();

        /// <summary>
        /// Key generation is not supported.
        /// </summary>
        public override void GenerateKey(ECCurve curve) =>
            throw new NotSupportedException();

        /// <inheritdoc/>
        public override string ToXmlString(bool includePrivateParameters)
        {
            if (includePrivateParameters)
                throw new CryptographicException("Private keys cannot be exported by this provider");

            return publicKey.ToXmlString(false);
        }

        /// <summary>
        /// Importing parameters from XML is not supported.
        public override void FromXmlString(string xmlString) =>
            throw new NotSupportedException();
    }
}
