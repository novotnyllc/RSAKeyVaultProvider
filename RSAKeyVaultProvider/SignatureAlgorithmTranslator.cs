using System;
using System.Security.Cryptography;

namespace Microsoft.Azure.KeyVault
{
    static class SignatureAlgorithmTranslator
    {
        public static string SignatureAlgorithmToJwsAlgId(HashAlgorithmName hashAlgorithmName)
        {
            if (hashAlgorithmName == HashAlgorithmName.SHA1)
                return "RSNULL";

            if (hashAlgorithmName == HashAlgorithmName.SHA256)
                return "RS256";

            if (hashAlgorithmName == HashAlgorithmName.SHA384)
                return "RS384";

            if (hashAlgorithmName == HashAlgorithmName.SHA512)
                return "RS512";
            
            throw new NotSupportedException("The algorithm specified is not supported.");
        }
    }
}
