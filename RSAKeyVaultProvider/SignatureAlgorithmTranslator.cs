using System;
using System.Security.Cryptography;

using Azure.Security.KeyVault.Keys.Cryptography;

namespace RSAKeyVaultProvider
{
    static class SignatureAlgorithmTranslator
    {
        public static SignatureAlgorithm SignatureAlgorithmToJwsAlgId(HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName == HashAlgorithmName.SHA1)
                return new SignatureAlgorithm("RSNULL");

            if (hashAlgorithmName == HashAlgorithmName.SHA256)
                return SignatureAlgorithm.RS256;

            if (hashAlgorithmName == HashAlgorithmName.SHA384)
                return SignatureAlgorithm.RS384;

            if (hashAlgorithmName == HashAlgorithmName.SHA512)
                return SignatureAlgorithm.RS512;
            
            throw new NotSupportedException("The algorithm specified is not supported.");
        }
    }
}
