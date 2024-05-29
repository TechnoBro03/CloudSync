using CloudSync.Utilities;

namespace CloudSync
{
    public static class DataBase
    {
        public static readonly string root = Path.Combine(Directory.GetCurrentDirectory(),"Users");
        // Make all use User objects instead of directories.

        // Get all files in specified directory.
        public static string[] GetFiles(User u)
        {
            // Get all files, remove path, keep just file name
            string[] files = Directory.GetFiles(GetUserDirectory(u, true));
            List<string> filesL = files.ToList();
            for(int i = 0; i < filesL.Count; i++)
            {
                filesL[i] = Path.GetFileName(filesL[i]);
            }
            // Remove the user.dat file from the list
            int index = filesL.IndexOf("user.dat");
            if(index != -1)
                filesL.RemoveAt(index);
            return filesL.ToArray();
        }
        //Delete file at specified path.
        public static void DeleteFile(User u, string fileName)
        {
            string path = Path.Combine(GetUserDirectory(u, true), fileName);
            File.Delete(path);
        }

        //Read file at specified path in 'bufferSize' byte chunks.
        public static byte[] ReadFromFile(User u, string fileName, int bufferSize, int offset)
        {
            string path = Path.Combine(GetUserDirectory(u, true), fileName);
            return FileIO.ReadFromFile(path, bufferSize, offset);
        }
        // Create new and/or append to file at specified path.
        public static void WriteToFile(User u, string fileName, byte[] data)
        {
            string path = Path.Combine(GetUserDirectory(u, true), fileName);
            FileIO.WriteToFile(path, data);
        }
        // Gets the directory associated with User
        // If the User is stored as plaintext, hashed will be false.
        // If the User is stored as hashed values, hashed will be true.
        public static string GetUserDirectory(User u, bool hashed)
        {
            if(hashed)
                return Path.Combine(root, u.Username);
            return Path.Combine(root, u.HashedUsername);
        }
        public static void SaveUser(User u)
        {
            // Create directory for user if it does not exist
            string userDirectory = GetUserDirectory(u, false);
            Directory.CreateDirectory(userDirectory);
            string path = Path.Combine(userDirectory, "user.dat");

            using BinaryWriter bW = new(new FileStream(path, FileMode.Create));
            bW.Write(u.HashedUsername);
            bW.Write(u.HashedPassword);
        }
        // Simple lookup, a User not existing is normal, therefor, return null.
        public static User? GetUser(string username)
        {
            User storedUser = User.CreateTemp(username, "");
            string path = Path.Combine(GetUserDirectory(storedUser, false), "user.dat");

            if(!Path.Exists(path))
                return null;
            
            using BinaryReader br = new(new FileStream(path, FileMode.Open));
            storedUser.Username = br.ReadString();
            storedUser.Password = br.ReadString();
            return storedUser;
        }
    }
}