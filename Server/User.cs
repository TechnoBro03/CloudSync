using CloudSync.Cryptography;
using CloudSync.Utilities;
namespace CloudSync
{
    public class User
    {
        private string username;
        private string password;
        // DateTime lastAccess; // For security
        // DateTime accountCreation; // For recommended password changes
        public string Username
        {
            get => username;
            set
            {
                if(string.IsNullOrWhiteSpace(value) || value.Length < 6)
                    throw new Exception("Username must be at least 6 characters.");
                // if(!value.IsAlphaNumeric())
                //     throw new Exception("Username can only contain alphanumeric characters and underscores.");
                username = value;
            }
        }
        public string Password
        {
            get => password;
            set
            {
                if(string.IsNullOrWhiteSpace(value) || value.Length < 6)
                    throw new Exception("Password must be at least 6 characters.");
                // if(!value.IsAlphaNumeric())
                //     throw new Exception("Password can only contain alphanumeric characters and underscores.");
                password = value;
            }
        }
        public string HashedUsername
        {
            get => Cipher.Hash256(username.ToByteArray()).ToBase64URLString();
        }
        public string HashedPassword
        {
            get => Cipher.Hash256(username.ToByteArray()).ToBase64URLString();
        }
        private User() {}
        // Create new User in database.
        public User(string username, string password)
        {
            Username = username;
            Password = password;
        }
        // Creates a User object without validation
        public static User CreateTemp(string username, string password)
        {
            User u = new()
            {
                username = username,
                password = password
            };
            return u;
        }
    }
}