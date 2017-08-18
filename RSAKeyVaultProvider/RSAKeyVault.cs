using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Microsoft.Azure.KeyVault
{
    public sealed class RSAKeyVault : RSA
    {
        readonly KeyVaultContext context;
        RSA publicKey;

        public RSAKeyVault(KeyVaultContext context)
        {
            if (!context.IsValid)
                throw new ArgumentException("Must not be the default", nameof(context));

            this.context = context;
            publicKey = context.Key.ToRSA();
            KeySizeValue = publicKey.KeySize;
            LegalKeySizesValue = new[] { new KeySizes(publicKey.KeySize, publicKey.KeySize, 0) };
        }

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            // Key Vault's API is known to use CA(false) everywhere. This should not deadlock.
            return SignHashAsync(hash, hashAlgorithm, padding).GetAwaiter().GetResult();
        }

        public async Task<byte[]> SignHashAsync(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            CheckDisposed();

            // Key Vault only supports PKCSv1 padding
            if (padding.Mode != RSASignaturePaddingMode.Pkcs1)
                throw new CryptographicException("Unsupported padding mode");

            try
            {
                return await context.SignDigestAsync(hash, hashAlgorithm);
            }
            catch (Exception e)
            {
                throw new CryptographicException("Error calling Key Vault", e);
            }
        }

        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            CheckDisposed();

            // Verify can be done locally using the public key
            return publicKey.VerifyHash(hash, signature, hashAlgorithm, padding);
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            CheckDisposed();

            using (var digestAlgorithm = GetHashAlgorithm(hashAlgorithm))
            {
                return digestAlgorithm.ComputeHash(data, offset, count);
            }
        }   

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            CheckDisposed();

            using (var digestAlgorithm = GetHashAlgorithm(hashAlgorithm))
            {
                return digestAlgorithm.ComputeHash(data);
            }
        }

        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
                // Key Vault's API is known to use CA(false) everywhere. This should not deadlock.
            return DecryptAsync(data, padding).GetAwaiter().GetResult();
        }

        public async Task<byte[]> DecryptAsync(byte[] data, RSAEncryptionPadding padding)
        {
            CheckDisposed();

            try
            {
                return await context.DecryptDataAsync(data, padding);
            }
            catch (Exception e)
            {
                throw new CryptographicException("Error calling Key Vault", e);
            }
        }

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
        {
            CheckDisposed();

            return publicKey.Encrypt(data, padding);
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            CheckDisposed();

            if (includePrivateParameters)
                throw new CryptographicException("Private keys cannot be exported by this provider");

            return context.Key.ToRSAParameters();
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            throw new NotSupportedException();
        }

        void CheckDisposed()
        {
            if (publicKey == null)
                throw new ObjectDisposedException($"{nameof(RSAKeyVault)} is disposed");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                publicKey?.Dispose();
                publicKey = null;
            }

            base.Dispose(disposing);
        }

        private static HashAlgorithm GetHashAlgorithm(HashAlgorithmName algorithm)
        {
            if (algorithm == HashAlgorithmName.SHA256)
                return SHA256.Create();

            if (algorithm == HashAlgorithmName.SHA384)
                return SHA384.Create();

            if (algorithm == HashAlgorithmName.SHA512)
                return SHA512.Create();

            throw new NotSupportedException("The specified algorithm is not supported.");
        }
    }
}
