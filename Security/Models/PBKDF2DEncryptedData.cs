namespace Security.Models
{
    public class PBKDF2DEncryptedData
    {
        public byte[] Cipher{ get; set; }
        public byte[] IV { get; set; }
        public byte[] Salt { get; set; }
    }
}
