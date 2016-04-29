using System;
using System.IO;
using System.Text;
using Security.Models;
using Security.Encryptors;

namespace PBKDF2_Test_App
{
    using DAL.Security;
    using Enum;
    using Security.Hashing;
    public class Program
    {
        private const string Path = @"C:\Users\wvoyle\Desktop\TestHashed\{0}.txt";

        public static void Main(string[] args)
        {
            Console.WriteLine("Press 'E' to Encrypt, 'D' to Decrypt, 'H' to Hash...");
            var decision = Console.ReadLine().ToUpper().Trim();

            switch (decision)
            {
                case "E":
                    EncryptProcess();
                    break;
                case "D":
                    DecryptProcess();
                    break;
                case "H":
                    HashData();
                    break;
                default:
                    throw new EntryPointNotFoundException();
            }
        }

        private static void HashData()
        {
            Console.WriteLine("Enter data to Hash...");
            string data = Console.ReadLine();

            ValidateData(data);

            PBKDF2ManagedHashing _pbkdf2ManagedHashing = new PBKDF2ManagedHashing();
            var hashedData = _pbkdf2ManagedHashing.HashData(data);

            File.WriteAllBytes(Path.Replace("{0}", DataType.Salt.ToString()), hashedData.Salt);
            File.WriteAllBytes(Path.Replace("{0}", DataType.Hashed.ToString()), hashedData.Cipher);

            Console.WriteLine("Data Hashed!");
            Console.WriteLine("Enter data to compare...");

            string compareData = Console.ReadLine();

            ValidateData(compareData);

            var compareHashedData = new PBKDF2HashedData();

            compareHashedData.Salt = File.ReadAllBytes(Path.Replace("{0}", DataType.Salt.ToString()));
            compareHashedData.Cipher = File.ReadAllBytes(Path.Replace("{0}", DataType.Hashed.ToString()));

            var newHashedData = _pbkdf2ManagedHashing.HashData(compareData, compareHashedData.Salt);

            if (_pbkdf2ManagedHashing.ValidateCipherData(hashedData.Cipher, newHashedData.Cipher))
                Console.WriteLine("Matched!");
            else
                Console.WriteLine("Not Matched...");

            Console.ReadLine();
        }

        private static void EncryptProcess()
        {
            Console.WriteLine("Enter data to encrypt...");
            string data = Console.ReadLine();

            ValidateData(data);

            PBKDF2ManagedEncryption _PBKDF2Encryption = new PBKDF2ManagedEncryption();
            Queries db = new Queries();

            var encryptedData = _PBKDF2Encryption.Encrypt(data);
            db.InsertCipherIntoDb(encryptedData.Cipher, encryptedData.IV, encryptedData.Salt);

            File.WriteAllBytes(Path.Replace("{0}", DataType.Data.ToString()), encryptedData.Cipher);
            File.WriteAllBytes(Path.Replace("{0}", DataType.IV.ToString()), encryptedData.IV);
            File.WriteAllBytes(Path.Replace("{0}", DataType.Salt.ToString()), encryptedData.Salt);

            Console.WriteLine("Data Encypted!");
        }

        private static void DecryptProcess()
        {
            //Console.WriteLine(string.Format("Decrypt Data at {0} (Y/N) ?", Path.Remove(Path.IndexOf("{0}"))));
            //var decision = Console.ReadLine().ToUpper().Trim();

            //if (decision != "Y")
            //    return;

            Console.WriteLine("Enter Cipher ID...");
            int cipherId = TryParseInt(Console.ReadLine());


            Queries db = new Queries();
            var encryptedDataDto = db.SelectCipherDataFromDb(cipherId);

            PBKDF2DEncryptedData encryptedData = new PBKDF2DEncryptedData
            {
                Cipher = encryptedDataDto.Cipher,
                IV = encryptedDataDto.IV,
                Salt = encryptedDataDto.Salt
            };

            //encryptedData.Cipher = File.ReadAllBytes(Path.Replace("{0}", DataType.Data.ToString()));
            //encryptedData.IV = File.ReadAllBytes(Path.Replace("{0}", DataType.IV.ToString()));
            //encryptedData.Salt = File.ReadAllBytes(Path.Replace("{0}", DataType.Salt.ToString()));

            PBKDF2ManagedEncryption _PBKDF2Encryption = new PBKDF2ManagedEncryption();

            var decryptedData = _PBKDF2Encryption.Decrypt(encryptedData);

            Console.WriteLine(string.Format("Decrypted Data: {0}", decryptedData));
            Console.ReadLine();
        }

        private static int TryParseInt(string data)
        {
            int result;
            var success = int.TryParse(data, out result);

            if (success)
            {
                return result;
            }

            throw new InvalidCastException();
        }

        private static void ValidateData(string data)
        {
            if (string.IsNullOrWhiteSpace(data))
                throw new NotImplementedException();
        }

        private static byte[] ConvertStringToByteArray(string data)
        {
            return new UTF8Encoding(false).GetBytes(data);
        }
    }
}
