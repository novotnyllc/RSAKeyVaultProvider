using System.Threading.Tasks;
using System.Security.Cryptography;
using Xunit;

namespace RSAKeyVaultProviderTests
{
    public class KeyVaultSigningContextTests
    {
        private readonly AzureKeyVaultSignConfigurationSet _configuration;

        public KeyVaultSigningContextTests()
        {
            var creds = TestAzureCredentials.Credentials;
            if (creds == null)
            {
                return;
            }
            _configuration = new AzureKeyVaultSignConfigurationSet
            {
                AzureClientId = creds.ClientId,
                AzureClientSecret = creds.ClientSecret,
                AzureKeyVaultUrl = creds.AzureKeyVaultUrl,
                AzureKeyVaultKeyName = creds.AzureKeyVaultCertificateName,
                Mode = KeyVaultMode.Certificate
            };
        }
 
    }
}
