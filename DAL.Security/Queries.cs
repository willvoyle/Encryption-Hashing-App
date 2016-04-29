using DAL.Security.Dto;
using System;
using System.Data;
using System.Data.SqlClient;

namespace DAL.Security
{
    public class Queries
    {
        private const string connectionString = @"Server=356331-DPDP-DBA\ECOM_DEV,41433;Database=dominos_online;User Id=usrHitachi;Password=hitachi#2015!;";

        private void ExecuteDbCommand(SqlCommand command)
        {
            using (SqlConnection con = new SqlConnection(connectionString))
            {
                command.Connection = con;

                con.Open();
                command.ExecuteNonQuery();

                con.Close();
            }
        }

        private PBKDF2DEncryptedDataDto ExecuteDbQuery(SqlCommand command)
        {
            using (SqlConnection con = new SqlConnection(connectionString))
            {
                command.Connection = con;

                con.Open();
                var result = MapCipherDataToDto(command.ExecuteReader());

                con.Close();

                return result;
            }
        }

        public void InsertCipherIntoDb(byte[] cipher, byte[] iV, byte[] salt)
        {
            using (SqlCommand cmd = new SqlCommand("InsertCipherText"))
            {
                cmd.CommandType = CommandType.StoredProcedure;

                SqlParameter cipherParm = cmd.Parameters.Add("@CipherText", SqlDbType.VarBinary);
                cipherParm.Value = cipher;

                SqlParameter ivParm = cmd.Parameters.Add("@IV", SqlDbType.VarBinary);
                ivParm.Value = iV;

                SqlParameter saltParm = cmd.Parameters.Add("@Salt", SqlDbType.VarBinary);
                saltParm.Value = salt;

                ExecuteDbCommand(cmd);
            }
        }

        public PBKDF2DEncryptedDataDto SelectCipherDataFromDb(int cipherId)
        {
            string querySql = "SELECT * FROM [tCipherText] WHERE id = @ID";

            using (SqlCommand cmd = new SqlCommand(querySql))
            {
                SqlParameter cipherParm = cmd.Parameters.Add("@ID", SqlDbType.Int);
                cipherParm.Value = cipherId;

                return ExecuteDbQuery(cmd);
            }
        }

        private PBKDF2DEncryptedDataDto MapCipherDataToDto(SqlDataReader reader)
        {
            while (reader.Read())
            {
                return new PBKDF2DEncryptedDataDto
                {
                    Cipher = (byte[])reader["cipherText"],
                    IV = (byte[])reader["iv"],
                    Salt = (byte[])reader["salt"]
                };
            }

            return null;
        }
    }
}
