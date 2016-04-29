using Security.Models;

namespace Security.Encryptors.Interfaces
{
    public interface IPBKDF2Encryption
    {
        PBKDF2DEncryptedData Encrypt(string data);

        string Decrypt(PBKDF2DEncryptedData encryptedDto);
    }
}
