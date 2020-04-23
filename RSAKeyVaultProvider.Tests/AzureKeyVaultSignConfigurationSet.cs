

using System;

namespace RSAKeyVaultProviderTests
{
    public enum KeyVaultMode
    {
        Key,
        Certificate
    }
    public sealed class AzureKeyVaultSignConfigurationSet
    {
        public bool ManagedIdentity { get; set; }
        public string AzureClientId { get; set; }
        public string AzureClientSecret { get; set; }
        public string AzureTenantId { get; set; }
        public Uri AzureKeyVaultUrl { get; set; }
        public string AzureKeyVaultKeyName { get; set; }
        public string AzureAccessToken { get; set; }
        public KeyVaultMode Mode { get; set; }
        
        public bool Validate()
        {
            // Logging candidate.
            if (string.IsNullOrWhiteSpace(AzureAccessToken))
            {
                if(!ManagedIdentity)
                {
                    if (string.IsNullOrWhiteSpace(AzureClientId))
                    {
                        return false;
                    }
                    if (string.IsNullOrWhiteSpace(AzureClientSecret))
                    {
                        return false;
                    }
                    if(string.IsNullOrWhiteSpace(AzureTenantId))
                    {
                        return false;
                    }

                }                
            }
            
            if (AzureKeyVaultUrl == null)
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
