using System.IO;
using System.Reflection;
using Newtonsoft.Json;
using Xunit;

namespace RSAKeyVaultProviderTests
{
    public sealed class AzureFactAttribute : FactAttribute
    {
        public AzureFactAttribute()
        {
            if (TestAzureCredentials.Credentials == null)
            {
                Skip = "Test Azure credentials are not set up correctly. " +
                    "Please see the README for more information.";
            }
        }

        //Shadow the Skip as get only so it isn't set when an instance of the
        //attribute is declared
        public new string Skip {
            get => base.Skip;
            private set => base.Skip = value;
        }
    }

    public class TestAzureCredentials
    {
        public static TestAzureCredentials Credentials { get; }

        static TestAzureCredentials()
        {
            try
            {
                var basePath = Path.GetDirectoryName(typeof(TestAzureCredentials).GetTypeInfo().Assembly.Location);
                var credLocation = Path.Combine(basePath, @"private\azure-creds.json");
                var contents = File.ReadAllText(credLocation);
                Credentials = JsonConvert.DeserializeObject<TestAzureCredentials>(contents);
            }
            catch 
            {
            }
        }

        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string TenantId { get; set; }
        public string AzureKeyVaultUrl { get; set; }
        public string AzureKeyVaultCertificateName { get; set; }
        public string AzureKeyVaultECDsaCertificateName { get; set; }
        public string AzureKeyVaultKeyName { get; set; }
        public string AzureKeyVaultECDsaKeyName { get; set; }
    }
}
