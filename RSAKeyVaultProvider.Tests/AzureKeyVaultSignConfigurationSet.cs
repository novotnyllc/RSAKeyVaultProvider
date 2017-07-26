

namespace RSAKeyVaultProviderTests
{
    public enum KeyVaultMode
    {
        Key,
        Certificate
    }
    public sealed class AzureKeyVaultSignConfigurationSet
    {
        public string AzureClientId { get; set; }
        public string AzureClientSecret { get; set; }
        public string AzureKeyVaultUrl { get; set; }
        public string AzureKeyVaultKeyName { get; set; }
        public string AzureAccessToken { get; set; }
        public KeyVaultMode Mode { get; set; }
        
        public bool Validate()
        {
            // Logging candidate.
            if (string.IsNullOrWhiteSpace(AzureAccessToken))
            {
                if (string.IsNullOrWhiteSpace(AzureClientId))
                {
                    return false;
                }
                if (string.IsNullOrWhiteSpace(AzureClientSecret))
                {
                    return false;
                }
            }
            
            if (string.IsNullOrWhiteSpace(AzureKeyVaultUrl))
            {
                return false;
            }
            if (string.IsNullOrWhiteSpace(AzureKeyVaultKeyName))
            {
                return false;
            }
            return true;
        }
    }
}
