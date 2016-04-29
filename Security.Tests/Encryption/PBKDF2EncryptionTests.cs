using Security.Encryptors;
using Security.Encryptors.Interfaces;
using Security.Models;
using System.Text;
using Xunit;

namespace Security.Tests.Encryption
{
    public class PBKDF2EncryptionTests
    {
        private readonly IPBKDF2Encryption _PBKDF2Encryption;

        public PBKDF2EncryptionTests()
        {
            _PBKDF2Encryption = new PBKDF2ManagedEncryption();
        }

        [Fact]
        public void Decrypt_Should_Return_Correct_Plaint_Text()
        {
            string expected = "william.voyle@dominos.co.uk";

            var encryptedData = new PBKDF2DEncryptedData
            {
                Cipher = ConvertStringToByteArray("uCHm4SZ00a3+IQg+OUq1im0pMgoe4htTSHrMIMOwntk="),
                IV = ConvertStringToByteArray("m9GasrfNewA="),
                Salt = ConvertStringToByteArray("SFLzZmTuNeGrt0n3skSslw==")
            };

            string actual = _PBKDF2Encryption.Decrypt(encryptedData);

            Assert.Equal(expected, actual);
        }

        private static byte[] ConvertStringToByteArray(string data)
        {
            return new UTF8Encoding(false).GetBytes(data);
        }
    }
}
