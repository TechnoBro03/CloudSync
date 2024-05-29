using System.Text;
using System.Text.RegularExpressions;

namespace CloudSync.Utilities
{
    public static class Extensions
    {
        public static string ToBase64URLString(this byte[] value)
        {
            string base64 = Convert.ToBase64String(value);
            base64 = base64.Replace('/','-').Replace('+','_').Replace("=","");
            return base64;
        }
        public static bool IsAlphaNumeric(this string value)
        {
            Regex regex = new("^\\w+$");
            return regex.IsMatch(value);
        }

        public static byte[] ToByteArray(this string input, Encoding? encoding = null)
        {
            encoding ??= Encoding.UTF8; // Use UTF8 by default
            return encoding.GetBytes(input);
        }

        public static string FromByteArray(this byte[] value, Encoding? encoding = null)
        {
            encoding ??= Encoding.UTF8; // Use UTF8 by default
            return encoding.GetString(value);
        }
    }
}