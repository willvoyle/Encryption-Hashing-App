namespace DAL.Security.Dto
{
    public class PBKDF2DEncryptedDataDto
    {
        public byte[] Cipher { get; set; }
        public byte[] IV { get; set; }
        public byte[] Salt { get; set; }
    }
}
