using System;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Microsoft.Azure.KeyVault;

namespace RSAKeyVaultProviderTests
{
    public class RSAKeyVaultProviderTests
    {
        private readonly AzureKeyVaultSignConfigurationSet certificateConfiguration;
        private readonly AzureKeyVaultSignConfigurationSet keyConfiguration;

        public RSAKeyVaultProviderTests()
        {
            var creds = TestAzureCredentials.Credentials;
            if (creds == null)
            {
                return;
            }
            certificateConfiguration = new AzureKeyVaultSignConfigurationSet
            {
                AzureClientId = creds.ClientId,
                AzureClientSecret = creds.ClientSecret,
                AzureKeyVaultUrl = creds.AzureKeyVaultUrl,
                AzureKeyVaultKeyName = creds.AzureKeyVaultCertificateName,
                Mode = KeyVaultMode.Certificate
            };

            keyConfiguration = new AzureKeyVaultSignConfigurationSet
            {
                AzureClientId = creds.ClientId,
                AzureClientSecret = creds.ClientSecret,
                AzureKeyVaultUrl = creds.AzureKeyVaultUrl,
                AzureKeyVaultKeyName = creds.AzureKeyVaultKeyName,
                Mode = KeyVaultMode.Key
            };
        }

        [AzureFact]
        public async Task ShouldRoundTripASignatureWithCertificate()
        {
            using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(certificateConfiguration))
            {
                using (var rsa = materialized.ToRSA())
                using (var sha256 = SHA256.Create())
                {
                    var data = new byte[] { 1, 2, 3 };
                    var digest = sha256.ComputeHash(data);
                    var signature = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    var result = rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    Assert.True(result);
                }                
            }
        }

        [AzureFact]
        public async Task ShouldFailToVerifyBadSignatureWithCertificate()
        {
            using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(certificateConfiguration))
            {
                using (var rsa = materialized.ToRSA())
                using (var sha256 = SHA256.Create())
                {
                    var data = new byte[] { 1, 2, 3 };
                    var digest = sha256.ComputeHash(data);
                    var signature = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    signature[0] = (byte)~signature[0]; //Flip some bits.
                    var result = rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    Assert.False(result);
                }
                
            }
        }

        [AzureFact]
        public async Task ShouldHashDataAndVerifyWithCertificate()
        {
            using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(certificateConfiguration))
            {
                using (var rsa = materialized.ToRSA())
                {
                    var data = new byte[] { 1, 2, 3 };
                
                    var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    var result = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    Assert.True(result);
                }   
            }
        }

        [AzureFact]
        public async Task ShouldRoundTripEncryptAndDecrypt()
        {
            using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(keyConfiguration))
            {
                using (var rsa = materialized.ToRSA())
                {
                    var data = Encoding.UTF8.GetBytes("Clear text");
                    var cipherText = rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
                    var returnedData = rsa.Decrypt(cipherText, RSAEncryptionPadding.Pkcs1);
                    var text = Encoding.UTF8.GetString(returnedData);

                    Assert.Equal("Clear text", text);
                }
            }
        }

        [AzureFact]
        public async Task ShouldRoundTripASignatureWithKey()
        {
            using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(keyConfiguration))
            {
                using (var rsa = materialized.ToRSA())
                using (var sha256 = SHA256.Create())
                {
                    var data = new byte[] { 1, 2, 3 };
                    var digest = sha256.ComputeHash(data);
                    var signature = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    var result = rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    Assert.True(result);
                }
            }
        }

        [AzureFact]
        public async Task ShouldFailToVerifyBadSignatureWithKey()
        {
            using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(keyConfiguration))
            {
                using (var rsa = materialized.ToRSA())
                using (var sha256 = SHA256.Create())
                {
                    var data = new byte[] { 1, 2, 3 };
                    var digest = sha256.ComputeHash(data);
                    var signature = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    signature[0] = (byte)~signature[0]; //Flip some bits.
                    var result = rsa.VerifyHash(digest, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    Assert.False(result);
                }

            }
        }

        [AzureFact]
        public async Task ShouldHashDataAndVerifyWithKey()
        {
            using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(keyConfiguration))
            {
                using (var rsa = materialized.ToRSA())
                {
                    var data = new byte[] {1, 2, 3};

                    var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    var result = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    Assert.True(result);
                }
            }
        }

        [AzureFact]
        public async Task SignDataShouldThrowForUnsupportedHashAlgorithm()
        {
            using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(keyConfiguration))
            {
                using (var rsa = materialized.ToRSA())
                {
                    var exception = Assert.Throws<NotSupportedException>(() =>
                        rsa.SignData(Array.Empty<byte>(), new HashAlgorithmName("unsupported"), RSASignaturePadding.Pkcs1));

                    Assert.Equal("The specified algorithm is not supported.", exception.Message);
                }
            }
        }

        [AzureFact]
        public async Task VerifyDataShouldThrowForUnsupportedHashAlgorithm()
        {
            using (var materialized = await KeyVaultConfigurationDiscoverer.Materialize(keyConfiguration))
            {
                using (var rsa = materialized.ToRSA())
                {
                    var exception = Assert.Throws<NotSupportedException>(() =>
                        rsa.VerifyData(Array.Empty<byte>(), Array.Empty<byte>(),
                            new HashAlgorithmName("unsupported"), RSASignaturePadding.Pkcs1));

                    Assert.Equal("The specified algorithm is not supported.", exception.Message);
                }
            }
        }

        [Fact]
        public void DefaultContextShouldThrow()
        {
            Assert.Throws<ArgumentException>(() => new RSAKeyVault(default(KeyVaultContext)));
        }
    }
}
