using System;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Xunit;
using RSAKeyVaultProvider;

namespace RSAKeyVaultProviderTests
{
    public class ECDsaKeyVaultProviderTests
    {
        private readonly AzureKeyVaultSignConfigurationSet certificateConfiguration;
        private readonly AzureKeyVaultSignConfigurationSet keyConfiguration;
        private readonly AzureKeyVaultSignConfigurationSet certificateWithMSIConfiguration;

        public ECDsaKeyVaultProviderTests()
        {
            var creds = TestAzureCredentials.Credentials;
            if (creds is null)
            {
                return;
            }
            certificateConfiguration = new AzureKeyVaultSignConfigurationSet
            {
                AzureClientId = creds.ClientId,
                AzureClientSecret = creds.ClientSecret,
                AzureTenantId = creds.TenantId,
                AzureKeyVaultUrl = new Uri(creds.AzureKeyVaultUrl),
                AzureKeyVaultKeyName = creds.AzureKeyVaultECDsaCertificateName,

                Mode = KeyVaultMode.Certificate
            };

            keyConfiguration = new AzureKeyVaultSignConfigurationSet
            {
                AzureClientId = creds.ClientId,
                AzureClientSecret = creds.ClientSecret,
                AzureTenantId = creds.TenantId,
                AzureKeyVaultUrl = new Uri(creds.AzureKeyVaultUrl),
                AzureKeyVaultKeyName = creds.AzureKeyVaultECDsaKeyName,
                Mode = KeyVaultMode.Key
            };

            certificateWithMSIConfiguration = new AzureKeyVaultSignConfigurationSet
            {
                ManagedIdentity = true,
                AzureKeyVaultUrl = new Uri(creds.AzureKeyVaultUrl),
                AzureKeyVaultKeyName = creds.AzureKeyVaultECDsaCertificateName,
                Mode = KeyVaultMode.Certificate
            };
        }

        [AzureFact]
        public async Task ShouldRoundTripASignatureWithCertificate()
        {
            var materialized = await KeyVaultConfigurationDiscoverer.Materialize(certificateConfiguration);

            using (var ecdsa = materialized.ToECDsa())
            using (var sha256 = SHA256.Create())
            {
                var data = new byte[] { 1, 2, 3 };
                var digest = sha256.ComputeHash(data);
                var signature = ecdsa.SignHash(digest);
                var result = ecdsa.VerifyHash(digest, signature);
                Assert.True(result);
            }
        }


        [AzureFact]
        public async Task ShouldRoundTripASignatureWithCertificateViaMsi()
        {
            var materialized = await KeyVaultConfigurationDiscoverer.Materialize(certificateWithMSIConfiguration);

            using (var ecdsa = materialized.ToECDsa())
            using (var sha256 = SHA256.Create())
            {
                var data = new byte[] { 1, 2, 3 };
                var digest = sha256.ComputeHash(data);
                var signature = ecdsa.SignHash(digest);
                var result = ecdsa.VerifyHash(digest, signature);
                Assert.True(result);
            }
        }

        [AzureFact]
        public async Task ShouldFailToVerifyBadSignatureWithCertificate()
        {
            var materialized = await KeyVaultConfigurationDiscoverer.Materialize(certificateConfiguration);
            using (var ecdsa = materialized.ToECDsa())
            using (var sha256 = SHA256.Create())
            {
                var data = new byte[] { 1, 2, 3 };
                var digest = sha256.ComputeHash(data);
                var signature = ecdsa.SignHash(digest);
                signature[0] = (byte)~signature[0]; //Flip some bits.
                var result = ecdsa.VerifyHash(digest, signature);
                Assert.False(result);
            }
        }

        [AzureFact]
        public async Task ShouldHashDataAndVerifyWithCertificate()
        {
            var materialized = await KeyVaultConfigurationDiscoverer.Materialize(certificateConfiguration);
            using (var ecdsa = materialized.ToECDsa())
            {
                var data = new byte[] { 1, 2, 3 };

                var signature = ecdsa.SignData(data, HashAlgorithmName.SHA256);
                var result = ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
                Assert.True(result);
            }
        }

        [AzureFact]
        public async Task ShouldRoundTripASignatureWithKey()
        {
            var materialized = await KeyVaultConfigurationDiscoverer.Materialize(keyConfiguration);
            using (var ecdsa = materialized.ToECDsa())
            using (var sha256 = SHA256.Create())
            {
                var data = new byte[] { 1, 2, 3 };
                var digest = sha256.ComputeHash(data);
                var signature = ecdsa.SignHash(digest);
                var result = ecdsa.VerifyHash(digest, signature);
                Assert.True(result);
            }
        }

        [AzureFact]
        public async Task ShouldFailToVerifyBadSignatureWithKey()
        {
            var materialized = await KeyVaultConfigurationDiscoverer.Materialize(keyConfiguration);
            using (var ecdsa = materialized.ToECDsa())
            using (var sha256 = SHA256.Create())
            {
                var data = new byte[] { 1, 2, 3 };
                var digest = sha256.ComputeHash(data);
                var signature = ecdsa.SignHash(digest);
                signature[0] = (byte)~signature[0]; //Flip some bits.
                var result = ecdsa.VerifyHash(digest, signature);
                Assert.False(result);
            }
        }

        [AzureFact]
        public async Task ShouldHashDataAndVerifyWithKey()
        {
            var materialized = await KeyVaultConfigurationDiscoverer.Materialize(keyConfiguration);
            using (var ecdsa = materialized.ToECDsa())
            {
                var data = new byte[] { 1, 2, 3 };

                var signature = ecdsa.SignData(data, HashAlgorithmName.SHA256);
                var result = ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
                Assert.True(result);
            }
        }

        [AzureFact]
        public async Task SignDataShouldThrowForUnsupportedHashAlgorithm()
        {
            var materialized = await KeyVaultConfigurationDiscoverer.Materialize(certificateConfiguration);
            using (var ecdsa = materialized.ToECDsa())
            {
                var exception = Assert.Throws<NotSupportedException>(() =>
                    ecdsa.SignData(Array.Empty<byte>(), new HashAlgorithmName("unsupported")));

                Assert.Equal("The specified algorithm is not supported.", exception.Message);
            }
        }

        [AzureFact]
        public async Task VerifyDataShouldThrowForUnsupportedHashAlgorithm()
        {
            var materialized = await KeyVaultConfigurationDiscoverer.Materialize(certificateConfiguration);
            using (var ecdsa = materialized.ToECDsa())
            {
                var exception = Assert.Throws<NotSupportedException>(() =>
                    ecdsa.VerifyData(Array.Empty<byte>(), Array.Empty<byte>(),
                        new HashAlgorithmName("unsupported")));

                Assert.Equal("The specified algorithm is not supported.", exception.Message);
            }
        }

        [Fact]
        public void DefaultContextShouldThrow()
        {
            Assert.Throws<ArgumentException>(() => new ECDsaKeyVault(default(KeyVaultContext)));
        }
    }
}