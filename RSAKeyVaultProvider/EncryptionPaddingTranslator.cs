using System;
using System.Security.Cryptography;

namespace Microsoft.Azure.KeyVault
{
    static class EncryptionPaddingTranslator
    {
        public static string EncryptionPaddingToJwsAlgId(RSAEncryptionPadding padding)
        {
            switch (padding.Mode)
            {
                case RSAEncryptionPaddingMode.Pkcs1:
                    return "RSA1_5";
                case RSAEncryptionPaddingMode.Oaep when padding.OaepHashAlgorithm == HashAlgorithmName.SHA1:
                    return "RSA-OAEP";
                case RSAEncryptionPaddingMode.Oaep when padding.OaepHashAlgorithm == HashAlgorithmName.SHA256:
                    return "RSA-OAEP-256";
                default:
                    throw new NotSupportedException("The padding specified is not supported.");

            }
        }
    }
}
