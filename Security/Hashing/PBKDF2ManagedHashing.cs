using System.Security.Cryptography;

namespace Security.Hashing
{
    using Interfaces;
    using Models;

    public class PBKDF2ManagedHashing : IPBKDF2ManagedHashing
    {
        private const int SaltByteLength = 16;
        private const int IterationCount = 1000;
        private const int CipherLength = 20;

        public PBKDF2HashedData HashData(string data)
        {
            var salt = GenerateRandomSalt();
            return HashData(data, salt);
        }

        public PBKDF2HashedData HashData(string data, byte[] salt)
        {
            var rfc2898HashProvider = new Rfc2898DeriveBytes(data, salt, IterationCount);

            byte[] cipher = rfc2898HashProvider.GetBytes(CipherLength);

            return new PBKDF2HashedData { Salt = salt, Cipher = cipher };
        }

        public bool ValidateCipherData(byte[] cipher1, byte[] cipher2)
        {
            for (int i = 0; i < CipherLength; i++)
            {
                if (cipher1[i] != cipher2[i])
                {
                    return false;
                }
            }

            return true;
        }

        private static byte[] GenerateRandomSalt()
        {
            RNGCryptoServiceProvider cryptoService = new RNGCryptoServiceProvider();
            var salt = new byte[SaltByteLength];

            cryptoService.GetBytes(salt);

            return salt;
        }
    }
}
