using System.Security.Cryptography;

namespace CloudSync
{
    namespace Cryptography
    {
        public abstract class Cipher
        {
            public static byte[] Hash256(byte[] data)
            {
                return SHA256.HashData(data);
            }
            public static byte[] Hash128(byte[] data)
            {
                return MD5.HashData(data);
            }
            public abstract byte[] Encrypt(byte[] data);
            public abstract byte[] Decrypt(byte[] data);
        }
        public class XOR: Cipher
        {
            private byte[] key;
            public byte[] Key
            {
                get => key;
                set
                {
                    key = value ?? new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
                }
            }
            public override byte[] Encrypt(byte[] data)
            {
                for(int i = 0; i < data.Length; i++)
                    data[i] = (byte)(data[i] ^ Key[i % Key.Length]);
                return data;
            }
            public override byte[] Decrypt(byte[] data)
            {
                return Encrypt(data);
            }
            public XOR(byte[]? key = null)
            {
                Key = key!;
            }
        }
        public class AES : Cipher
        {
            private readonly Aes aes;
            public byte[] Key
            {
                get => aes.Key;
                set
                {
                    if (value == null || value.Length == 0)
                        throw new ArgumentNullException(nameof(Key));
                    aes.Key = value;
                }
            }
            public byte[] IV
            {
                get => aes.IV;
                set
                {
                    if (value == null || value.Length == 0)
                        throw new ArgumentNullException(nameof(IV));
                    aes.IV = value;
                }
            }
            // Expects 256 bit key and 128 bit IV
            public AES(byte[]? key = null, byte[]? iv = null)
            {
                aes = Aes.Create();
                if(key == null)
                    aes.GenerateKey();
                else
                    aes.Key = key;
                if(iv == null)
                    aes.GenerateIV();
                else
                    aes.IV = iv;
            }
            public override byte[] Encrypt(byte[] data)
            {
                return aes.EncryptCbc(data, aes.IV, PaddingMode.PKCS7);
            }
            public override byte[] Decrypt(byte[] data)
            {
                return aes.DecryptCbc(data, aes.IV, PaddingMode.PKCS7);
            }
        }
        public class RSA : Cipher
        {
            private readonly RSACryptoServiceProvider rsa;
            public byte[] PublicKey
            {
                get => rsa.ExportCspBlob(false);
                set
                {
                    if (value == null || value.Length == 0)
                        throw new ArgumentNullException(nameof(PublicKey));
                    rsa.ImportCspBlob(value);
                }
            }
            private byte[] PrivateKey
            {
                get => rsa.ExportCspBlob(true);
                set
                {
                    if (value == null || value.Length == 0)
                        throw new ArgumentNullException(nameof(PrivateKey));
                    rsa.ImportCspBlob(value);
                }
            }
            // Creates RSA with random key pair, unless public key is specified.
            public RSA(byte[]? publicKey = null)
            {
                rsa = new(4096);
                if(publicKey != null)
                    PublicKey = publicKey;
            }
            public override byte[] Encrypt(byte[] data)
            {
                return rsa.Encrypt(data, false);
            }
            public override byte[] Decrypt(byte[] data)
            {
                return rsa.Decrypt(data, false);
            }
        }
    }
}