using System.Net.Sockets;
using CloudSync.Cryptography;
using CloudSync.Utilities;

namespace CloudSync
{
    public struct Packet
    {
        private string command;
        public string Command
        {
            get => command;
            init
            {
                if(string.IsNullOrWhiteSpace(value) || value.Length != 4)
                    throw new ArgumentOutOfRangeException(nameof(Command), "Command must be 4 characters.");
                command = value;
            }
        }
        public bool LastPacket;
        public byte[] Data;
        public byte[] ToByteArray()
        {
            // Create byte array to store packet info
            byte[] packetBytes = new byte[4 + 1 + Data.Length]; // Command, LastPacket, Data
            // Cast info into byte arrays
            byte[] commandBytes = Command.ToByteArray();
            byte[] lastPacket = new byte[] { (byte)(LastPacket ? 1 : 0) };
            // Copy data into byte array
            Array.Copy(commandBytes, packetBytes, commandBytes.Length);
            Array.Copy(lastPacket, 0, packetBytes, 4, 1);
            Array.Copy(Data, 0, packetBytes, 5, Data.Length);
            return packetBytes;
        }
        public Packet(string command, bool lastPacket, byte[] data)
        {
            Command = command; LastPacket = lastPacket; Data = data;
        }
    }
    public static class PacketHandler
    {
        public static Packet ReceivePacket(Socket socket, Cipher? cipher = null)
        {
            // Get size of packet
            byte[] sizeBuffer = new byte[4];
            int bytesRead = socket.Receive(sizeBuffer, 0, 4, SocketFlags.None);
            int packetSize = BitConverter.ToInt32(sizeBuffer);

            // Get packet data
            byte[] packetBuffer = new byte[packetSize];
            bytesRead = socket.Receive(packetBuffer, 0, packetSize, SocketFlags.None);

            // Decrypt packet data
            byte[] packetData;
            if(cipher != null)
                packetData = cipher.Decrypt(packetBuffer);
            else
                packetData = packetBuffer;

            // Get info
            byte[] commandBuffer = packetData[..4];
            string command = commandBuffer.FromByteArray();
            bool lastPacket = packetData[4] != 0; // False if byte == 0, true otherwise
            byte[] data = packetData[5..];

            return new Packet(command, lastPacket, data);
        }
        public static void SendPacket(Socket socket, Packet packet, Cipher? cipher = null)
        {
            byte[] packetData;
            
            // Encrypt packet
            if(cipher != null)
                packetData = cipher.Encrypt(packet.ToByteArray());
            else
                packetData = packet.ToByteArray();
            
            // Byte array to store size + encrypted packet
            byte[] packetBytes = new byte[4 + packetData.Length]; // Size (4 bytes), packet size

            // Prefix size
            BitConverter.TryWriteBytes(packetBytes, packetData.Length);

            // Copy encrypted packet data
            Array.Copy(packetData, 0, packetBytes, 4, packetData.Length);

            // Send
            socket.Send(packetBytes);
        }
    }
}