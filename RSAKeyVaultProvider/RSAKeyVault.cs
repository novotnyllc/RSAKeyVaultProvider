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
            CheckDisposed();
            
            // Key Vault only supports PKCSv1 padding
            if (padding.Mode != RSASignaturePaddingMode.Pkcs1)
                throw new CryptographicException("Unsupported padding mode");

            try
            {
                // Put this on a task.run since we must make this sync
                return Task.Run(() => context.SignDigestAsync(hash, hashAlgorithm)).GetAwaiter().GetResult();
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

            // Need to call CryptoConfig since .NET Core 2 throws a PNSE with HashAlgorithm.Create
            using (var digestAlgorithm = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlgorithm.Name))
            {
                return digestAlgorithm.ComputeHash(data, offset, count);
            }
        }   

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            CheckDisposed();

            // Need to call CryptoConfig since .NET Core 2 throws a PNSE with HashAlgorithm.Create
            using (var digestAlgorithm = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlgorithm.Name))
            {
                return digestAlgorithm.ComputeHash(data);
            }
        }
        
        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
            CheckDisposed();

            try
            {
                // Put this on a task.run since we must make this sync
                return Task.Run(() => context.DecryptDataAsync(data, padding)).GetAwaiter().GetResult();
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

        // Obsolete, not used
        public override byte[] DecryptValue(byte[] rgb)
        {
            throw new NotSupportedException();
        }

        public override byte[] EncryptValue(byte[] rgb)
        {
            throw new NotSupportedException();
        }
    }
}
