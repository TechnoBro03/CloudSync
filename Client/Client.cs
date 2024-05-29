using System.Net;
using System.Net.Sockets;
using System.Security;
using CloudSync.Cryptography;
using CloudSync.Utilities;
namespace CloudSync
{
    public static class Client
    {
        public async static Task Main()
        {
            Console.WriteLine("Welcome to CloudSync!");
            Console.WriteLine("Please provide the server IP: ");
            string? ip = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(ip))
                ip = "127.0.0.1";

            // Connect to server
            IPEndPoint ipEndPoint = new(IPAddress.Parse(ip), 11000);
            using Socket socket = new(ipEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(ipEndPoint);

            // Generate public/private key pair
            RSA clientRSA = new();

            // Receive public key from server
            Packet serverPacket = PacketHandler.ReceivePacket(socket);
            RSA serverRSA = new(serverPacket.Data);

            // Send public key to server
            Packet clientPacket = new("PBKE", true, clientRSA.PublicKey);
            PacketHandler.SendPacket(socket, clientPacket); // Add RSA

            // Receive session symmetric key and IV
            serverPacket = PacketHandler.ReceivePacket(socket); // Add RSA
            byte[] key = serverPacket.Data;
            serverPacket = PacketHandler.ReceivePacket(socket); // Add RSA
            byte[] iv = serverPacket.Data;

            AES sessionAES = new(key, iv);

            while(true)
            {
                bool close = MainMenu(socket, sessionAES);
                if(close)
                {
                    // Shutdown and close
                    socket.Shutdown(SocketShutdown.Both);
                    socket.Close();
                    return;
                }
                UserMenu(socket, sessionAES);
            }
        }

        public static bool MainMenu(Socket socket, Cipher cipher)
        {
            while(true)
            {
                Console.Write("\nPlease pick an option:\n0) Sign in\n1) Create Account\n2) Exit\nOption: ");
                string input = Console.ReadLine() ?? "";
                int inputI;
                try
                {
                    inputI = int.Parse(input);
                    if(inputI < 0 || inputI > 2)
                        throw new ArgumentOutOfRangeException();
                }
                catch
                {
                    Console.WriteLine("Please enter a valid option...");
                    continue;
                }
                switch(inputI)
                {
                    case 0:
                        // Send server login command
                        Packet clientPacket = new("LOGI", false, new byte[] {0});
                        PacketHandler.SendPacket(socket, clientPacket, cipher);

                        Console.Write("Enter username: ");
                        string username = Console.ReadLine() ?? "";
                        Console.Write("Enter password: ");
                        string password = Console.ReadLine() ?? "";

                        // Send username
                        clientPacket = new("USRN", false, username.ToByteArray());
                        PacketHandler.SendPacket(socket, clientPacket, cipher);

                        // Send password
                        clientPacket = new("PASS", true, password.ToByteArray());
                        PacketHandler.SendPacket(socket, clientPacket, cipher);

                        // Receive authentication
                        Packet serverPacket = PacketHandler.ReceivePacket(socket, cipher);
                        if(serverPacket.Command != "SUCC")
                            { Console.WriteLine("Username or password was incorrect"); break; }
                        return false;

                    case 1:
                        // Send server create account command
                        clientPacket = new("CRAC", false, new byte[] {0});
                        PacketHandler.SendPacket(socket, clientPacket, cipher);

                        Console.Write("Enter username: ");
                        username = Console.ReadLine() ?? "";
                        Console.Write("Enter password: ");
                        password = Console.ReadLine() ?? "";

                        // Send username
                        clientPacket = new("USRN", false, username.ToByteArray());
                        PacketHandler.SendPacket(socket, clientPacket, cipher);

                        // Send password
                        clientPacket = new("PASS", true, password.ToByteArray());
                        PacketHandler.SendPacket(socket, clientPacket, cipher);
                        
                        // Receive authentication
                        serverPacket = PacketHandler.ReceivePacket(socket, cipher);
                        if(serverPacket.Command != "SUCC")
                            { Console.WriteLine("Username or password was not valid"); break; }
                        return false;
                    case 2:
                        return true;
                }
            }
        }
        public static void UserMenu(Socket socket, Cipher cipher)
        {
            Console.WriteLine("Successfully authenticated!");
            while(true)
            {
                Console.Write("\nPlease pick an option:\n0) List files\n1) Download file\n2) Upload File\n3) Sign out\nOption: ");
                string input = Console.ReadLine() ?? "";
                int inputI;
                try
                {
                    inputI = int.Parse(input);
                    if(inputI < 0 || inputI > 4)
                        throw new ArgumentOutOfRangeException();
                }
                catch
                {
                    Console.WriteLine("Please enter a valid option...");
                    continue;
                }
                switch(inputI)
                {
                    case 0:
                        // Send list files command
                        Packet clientPacket = new("LSTF", true, new byte[] {0});
                        PacketHandler.SendPacket(socket, clientPacket, cipher);

                        // Receive files
                        Packet serverPacket = PacketHandler.ReceivePacket(socket, cipher);
                        Console.WriteLine(serverPacket.Data.FromByteArray());
                        break;
                    case 1:
                        Console.Write("Please enter file name: ");
                        string fileName = Console.ReadLine() ?? "";

                        // Send download file command
                        clientPacket = new("DWLD", true, fileName.ToByteArray());
                        PacketHandler.SendPacket(socket, clientPacket, cipher);

                        // Receive file data
                        serverPacket = PacketHandler.ReceivePacket(socket, cipher);
                        if(serverPacket.Command != "FDAT")
                            { Console.WriteLine("File not found"); break; }

                        // Write to file
                        FileIO.WriteToFile(Path.Combine(Directory.GetCurrentDirectory(),"Downloads", fileName), serverPacket.Data);
                        break;
                    case 2:
                        string filePath;
                        Console.Write("Please enter file path: ");
                        filePath = Console.ReadLine() ?? "";
                        fileName = new FileInfo(filePath).Name;

                        // Send upload file command
                        clientPacket = new("UPLD", false, fileName.ToByteArray());
                        PacketHandler.SendPacket(socket, clientPacket, cipher);

                        // Read file
                        try
                        {
                            byte[] fileData = FileIO.ReadFromFile(filePath, 1000000, 0);
                            // Send file data
                            clientPacket = new("UPLD", true, fileData);
                            PacketHandler.SendPacket(socket, clientPacket, cipher);
                        }
                        catch
                        {
                            Console.WriteLine("File not found");
                            clientPacket = new("FAIL", true, new byte[] {0});
                            PacketHandler.SendPacket(socket, clientPacket, cipher);
                        }
                        break;
                    case 3:
                            clientPacket = new("LOGO", true, new byte[] {0});
                            PacketHandler.SendPacket(socket, clientPacket, cipher);
                        return;
                }
            }
        }
    }
}