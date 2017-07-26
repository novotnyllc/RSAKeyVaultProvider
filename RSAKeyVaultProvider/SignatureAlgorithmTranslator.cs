using System;

namespace System.Security.Cryptography
{
    static class SignatureAlgorithmTranslator
    {
        public static string SignatureAlgorithmToJwsAlgId(SigningAlgorithm signatureAlgorithm, HashAlgorithmName hashAlgorithmName)
        {
            switch (signatureAlgorithm)
            {
                case SigningAlgorithm.RSA when hashAlgorithmName.Name == HashAlgorithmName.SHA256.Name:
                    return "RS256";
                case SigningAlgorithm.RSA when hashAlgorithmName.Name == HashAlgorithmName.SHA384.Name:
                    return "RS384";
                case SigningAlgorithm.RSA when hashAlgorithmName.Name == HashAlgorithmName.SHA512.Name:
                    return "RS512";

                case SigningAlgorithm.ECDSA when hashAlgorithmName.Name == HashAlgorithmName.SHA256.Name:
                    return "ES256";
                case SigningAlgorithm.ECDSA when hashAlgorithmName.Name == HashAlgorithmName.SHA384.Name:
                    return "ES384";
                case SigningAlgorithm.ECDSA when hashAlgorithmName.Name == HashAlgorithmName.SHA512.Name:
                    return "ES512";
                default:
                    throw new NotSupportedException("The algorithm specified is not supported.");

            }
        }
    }
}
