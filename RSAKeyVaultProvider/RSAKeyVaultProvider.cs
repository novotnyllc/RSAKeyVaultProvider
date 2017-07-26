using System;
using System.IO;
using System.Threading.Tasks;

namespace System.Security.Cryptography
{
    public sealed class RSAKeyVaultProvider : RSA
    {
        readonly KeyVaultContext context;
        RSA rsa;

        public RSAKeyVaultProvider(KeyVaultContext context)
        {
            this.context = context;
            rsa = context.Key.ToRSA();
            KeySizeValue = rsa.KeySize;
            LegalKeySizesValue = rsa.LegalKeySizes;
        }
        
        new static public RSAKeyVaultProvider Create() => Create("System.Security.Cryptography.RSAKeyVaultProvider");

        new static public RSAKeyVaultProvider Create(string algName) => (RSAKeyVaultProvider)CryptoConfig.CreateFromName(algName);
        
        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            CheckDisposed();
            
            // Key Vault only supports PKCSv1 padding
            if (padding.Mode != RSASignaturePaddingMode.Pkcs1)
                throw new CryptographicException(("Unsupported padding mode"));

            try
            {
                // Put this on a task.run since we must make this sync
                return Task.Run(() => context.SignDigestAsync(hash, hashAlgorithm)).Result;
            }
            catch (Exception e)
            {
                throw new CryptographicException("Error calling Key Vault", e);
            }
        }

        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            CheckDisposed();
            
            // Key Vault only supports PKCSv1 padding
            if (padding.Mode != RSASignaturePaddingMode.Pkcs1)
                throw new CryptographicException(("Unsupported padding mode"));

            // Verify can be done locally using the public key
            return rsa.VerifyHash(hash, signature, hashAlgorithm, padding);
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            CheckDisposed();
            
            using (var digestAlgorithm = HashAlgorithm.Create(hashAlgorithm.Name))
            {
                return digestAlgorithm.ComputeHash(data, offset, count);
            }
        }   

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            CheckDisposed();
            
            using (var digestAlgorithm = HashAlgorithm.Create(hashAlgorithm.Name))
            {
                return digestAlgorithm.ComputeHash(data);
            }
        }

        // We're not supporting encryption here 
        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
            CheckDisposed();
            
            if (!(padding.Mode == RSAEncryptionPaddingMode.Pkcs1 || 
                  RSAEncryptionPadding.OaepSHA1.Equals(padding) || 
                  RSAEncryptionPadding.OaepSHA256.Equals(padding)))
                throw new CryptographicException(("Unsupported padding mode"));

            try
            {
                // Put this on a task.run since we must make this sync
                return Task.Run(() => context.DecryptDataAsync(data, padding)).Result;
            }
            catch (Exception e)
            {
                throw new CryptographicException("Error calling Key Vault", e);
            }
        }

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
        {
            CheckDisposed();
                
            if (!(padding.Mode == RSAEncryptionPaddingMode.Pkcs1 || 
                  RSAEncryptionPadding.OaepSHA1.Equals(padding) || 
                  RSAEncryptionPadding.OaepSHA256.Equals(padding)))
                throw new CryptographicException(("Unsupported padding mode"));

            return rsa.Encrypt(data, padding);
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            CheckDisposed();
            
            if (includePrivateParameters)
                throw new CryptographicException(("Private keys cannot be exported by this provider"));

            return context.Key.ToRSAParameters();
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            throw new NotSupportedException();
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

        void CheckDisposed()
        {
            if (rsa == null)
                throw new ObjectDisposedException($"{nameof(RSAKeyVaultProvider)} is disposed");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                rsa?.Dispose();
                rsa = null;
            }
            
            base.Dispose(disposing);
        }
    }
}
