using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using CloudSync.Cryptography;
using CloudSync.Utilities;
// Delegate dictionary, return parent class with subclass objects, data[] parameter
// Generate public/private key on username / password?
// Nonce
// Salt
// User changing
// Fix RSA
namespace CloudSync
{
    public static class Server
    {
        static Socket socket;
        static ConcurrentBag<Socket> activeSessions = new();
        public static async Task Main()
        {
            CancellationTokenSource cancellationTokenSource = new();

            Task serverTask = StartAsync(cancellationTokenSource.Token);

            while(true) { if(Console.ReadLine() == "STOP") {break;} }

            Shutdown(cancellationTokenSource);

            await serverTask;
            Console.WriteLine("Shutdown complete");
        }
        public static async Task StartAsync(CancellationToken token)
        {
            Console.WriteLine("Server: Binding to local IP...");

            // Bind to local IP
            IPEndPoint ipEndPoint = new(IPAddress.Parse("127.0.0.1"), 11000);
            socket = new(ipEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(ipEndPoint);

            // Set socket into listening state
            socket.Listen();

            // WaitForShutDown();

            while(!token.IsCancellationRequested)
            {
                Console.WriteLine("Server: Listening...");
                try
                {
                    Socket clientSocket = await socket.AcceptAsync(token);
                    activeSessions.Add(clientSocket);
                    Task.Run(() => HandleClient(clientSocket)); // Handle client on a separate thread

                    Console.WriteLine($"Server: Connected to client {clientSocket.RemoteEndPoint}");
                }
                catch(OperationCanceledException) {Console.WriteLine("Server: Listening task canceled...");}
            }
        }
        public static void Shutdown(CancellationTokenSource source)
        {
            Console.WriteLine("Server: Shutting down...");
            source.Cancel();
            Console.WriteLine("Server: Closing all connections...");

            foreach(Socket socket in activeSessions)
            {
                socket.Shutdown(SocketShutdown.Both);
                socket.Close();
            }

            activeSessions.Clear();
            socket.Close();
        }
        public static void HandleClient(Socket socket)
        {
            // Generate public/private key pair
            RSA serverRSA = new();

            // Send public key
            Packet serverPacket = new("PBKE", true, serverRSA.PublicKey);
            PacketHandler.SendPacket(socket, serverPacket);

            // Receive client public key
            Packet clientPacket = PacketHandler.ReceivePacket(socket); // Add RSA
            RSA clientRSA = new(clientPacket.Data);
            
            // Generate symmetric key/iv
            AES sessionAES = new();

            // Send key/iv
            serverPacket = new("SKEY", false, sessionAES.Key);
            PacketHandler.SendPacket(socket, serverPacket); // Add RSA
            serverPacket = new("SSIV", true, sessionAES.IV);
            PacketHandler.SendPacket(socket, serverPacket); // Add RSA

            while(true)
            {
                User user = MainMenu(socket, sessionAES);
                UserMenu(socket, sessionAES, user);
            }
        }
        public static User MainMenu(Socket socket, Cipher cipher)
        {
            while(true)
            {
                // Receive command from client
                Packet clientPacket = PacketHandler.ReceivePacket(socket, cipher);
                switch(clientPacket.Command)
                {
                    case "LOGI":
                        // Receive username
                        clientPacket = PacketHandler.ReceivePacket(socket, cipher);
                        string username = clientPacket.Data.FromByteArray();

                        // Receive password
                        clientPacket = PacketHandler.ReceivePacket(socket, cipher);
                        string password = clientPacket.Data.FromByteArray();

                        // Authenticate user
                        User? user = UserManager.Authenticate(username, password);

                        if(user != null)
                        {
                            // Send successful authentication command
                            Packet serverPacket = new("SUCC", true, new byte[] {0});
                            PacketHandler.SendPacket(socket, serverPacket, cipher);
                            return user;
                        }
                        // Send failed authentication
                        PacketHandler.SendPacket(socket, new Packet("FAIL", true, new byte[] {0}), cipher);
                        break;
                
                    case "CRAC":
                        // Receive username
                        clientPacket = PacketHandler.ReceivePacket(socket, cipher);
                        username = clientPacket.Data.FromByteArray().Trim();

                        // Receive password
                        clientPacket = PacketHandler.ReceivePacket(socket, cipher);
                        password = clientPacket.Data.FromByteArray().Trim();

                        // Crate user
                        try
                        {
                            UserManager.CreateUser(username, password);
                            user = UserManager.Authenticate(username, password);
                            if(user != null) // Won't be null, since user was just created successfully
                            {
                                Packet serverPacket = new("SUCC", true, new byte[] {0});
                                PacketHandler.SendPacket(socket, serverPacket, cipher);
                                return user;
                            }
                        }
                        catch(Exception e) { Console.WriteLine(e.Message);}
                        // Send failed authentication
                        PacketHandler.SendPacket(socket, new Packet("FAIL", true, new byte[] {0}), cipher);
                        break;
                }
            }
        }
        public static void UserMenu(Socket socket, Cipher cipher, User user)
        {
            while(true)
            {
                // Receive command from client
                Packet clientPacket = PacketHandler.ReceivePacket(socket, cipher);
                switch(clientPacket.Command)
                {
                    case "LSTF":
                        string[] files = DataBase.GetFiles(user);
                        string filesS = string.Join('\n', files);
                        Packet serverPacket = new("FLST", true, filesS.ToByteArray());
                        PacketHandler.SendPacket(socket, serverPacket, cipher);
                        break;

                    case "DWLD":
                        // Get file name
                        string fileName = clientPacket.Data.FromByteArray();
                        try
                        {
                            byte[] fileData = DataBase.ReadFromFile(user, fileName, 1000000, 0);
                            clientPacket = new("FDAT", true, fileData);
                            PacketHandler.SendPacket(socket, clientPacket, cipher);
                            break;
                        }
                        catch
                        {
                            PacketHandler.SendPacket(socket, new Packet("FAIL", true, new byte[] {0}), cipher);
                            break;
                        }
                    case "UPLD":
                        // Get file name
                        fileName = clientPacket.Data.FromByteArray();

                        // Receive file data
                        clientPacket = PacketHandler.ReceivePacket(socket, cipher);

                        if(clientPacket.Command == "FAIL")
                            break;

                        // Write to file
                        DataBase.WriteToFile(user, fileName, clientPacket.Data);
                        break;
                    case "LOGO":
                        return;
                }
            }
        }
    }
}