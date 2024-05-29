namespace CloudSync.Utilities
{
    public static class FileIO
    {
        public static void WriteToFile(string path, byte[] data, FileMode mode = FileMode.Append)
        {
            using FileStream fs = new(path, mode, FileAccess.Write);
            fs.Write(data, 0, data.Length);
        }
        public static byte[] ReadFromFile(string path, int bufferSize, int offset)
        {
            using FileStream fs = new(path, FileMode.Open, FileAccess.Read);
            fs.Seek(offset, SeekOrigin.Begin);
            byte[] buffer = new byte[bufferSize];
            int bytesRead = fs.Read(buffer, 0, bufferSize);
            return buffer[..bytesRead]; // Return slice of array if less than bufferSize (may return 0 length array)
        }
    }
}