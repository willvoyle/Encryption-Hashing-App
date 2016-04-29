namespace Security.Models
{
    public class PBKDF2HashedData
    {
        public byte[] Salt { get; set; }
        public byte[] Cipher { get; set; }
    }
}
