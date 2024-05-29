namespace CloudSync
{
    public static class UserManager
    {
        private static bool VerifyUser(User user, User storedUser)
        {
            return user.HashedUsername == storedUser.Username &&
                   user.HashedPassword == storedUser.Password;
        }
        // Simple check, not authenticating is normal, therefor, return null
        public static User? Authenticate(string username, string password)
        {
            // Create User object
            User user = User.CreateTemp(username, password);
            // Get corresponding user stored in database (if present)
            User? storedUser = DataBase.GetUser(username);
            if(storedUser == null)
                return null;
            if(!VerifyUser(user, storedUser))
                return null;
            return storedUser;
        }
        // Can throw exceptions for invalid data or user already found.
        public static void CreateUser(string username, string password)
        {
            // Create User object
            User u = new(username, password);
            // Get corresponding User stored in database (if present)
            User? storedUser = DataBase.GetUser(username);
            if(storedUser != null)
                throw new Exception("That username is not available.");
            DataBase.SaveUser(u);
        }
        // Create ChangeUserInfo function(s)
    }
}