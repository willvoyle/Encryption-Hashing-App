using System.IO;
using System.Text;
using Security.Models;
using System.Security.Cryptography;

namespace Security.Encryptors
{
    using Interfaces;

    public class PBKDF2ManagedEncryption : IPBKDF2Encryption
    {
        private const int SaltByteLength = 16;

        public string Decrypt(PBKDF2DEncryptedData encryptedData)
        {
            using (TripleDES tripleDES = TripleDES.Create())
            {
                using (MemoryStream msDecrypt = new MemoryStream())
                {
                    tripleDES.Key = encryptedData.Salt;
                    tripleDES.IV = encryptedData.IV;

                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, tripleDES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        var encryptedDataByte = encryptedData.Cipher;

                        csDecrypt.Write(encryptedDataByte, 0, encryptedDataByte.Length);
                        csDecrypt.Flush();
                        csDecrypt.Close();
                    }

                    return ConvertByteArrayToString(msDecrypt.ToArray());
                }
            }
        }

        public PBKDF2DEncryptedData Encrypt(string data)
        {
            var salt = GenerateRandomSalt();

            using (TripleDES tripleDES = TripleDES.Create())
            {
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    tripleDES.Key = salt;

                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, tripleDES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        var dataByte = ConvertStringToByteArray(data);

                        csEncrypt.Write(dataByte, 0, dataByte.Length);
                        csEncrypt.FlushFinalBlock();
                        csEncrypt.Close();
                    }

                    return new PBKDF2DEncryptedData
                    {
                        Cipher = msEncrypt.ToArray(),
                        IV = tripleDES.IV,
                        Salt = tripleDES.Key
                    };
                }
            }
        }

        private static byte[] GenerateRandomSalt()
        {
            RNGCryptoServiceProvider cryptoService = new RNGCryptoServiceProvider();
            var salt = new byte[SaltByteLength];

            cryptoService.GetBytes(salt);

            return salt;
        }

        private static byte[] ConvertStringToByteArray(string data)
        {
            return new UTF8Encoding(false).GetBytes(data);
        }

        private static string ConvertByteArrayToString(byte[] data)
        {
            return new UTF8Encoding(false).GetString(data);
        }
    }
}
