using Security.Models;

namespace Security.Hashing.Interfaces
{
    public interface IPBKDF2ManagedHashing
    {
        PBKDF2HashedData HashData(string data);
        PBKDF2HashedData HashData(string data, byte[] salt);
    }
}
