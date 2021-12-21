using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Bridge.Commons.Cryptography
{
    /// <summary>
    ///     Extensão de criptografia
    /// </summary>
    public static class SymmetricCryptographyExtension
    {
        /// <summary>
        ///     Encriptador
        /// </summary>
        /// <param name="message"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="rfc2898KeygenIterations"></param>
        /// <param name="aesKeySizeInBits"></param>
        /// <param name="paddingMode"></param>
        /// <returns></returns>
        public static byte[] EncryptAes(this byte[] message, string password, byte[] salt,
            int rfc2898KeygenIterations = 100, int aesKeySizeInBits = 128,
            PaddingMode paddingMode = PaddingMode.ISO10126)
        {
            byte[] cipherText = null;

            using (Aes aes = new AesManaged())
            {
                aes.Padding = paddingMode;
                aes.KeySize = aesKeySizeInBits;
                var keyStrengthInBytes = aes.KeySize / 8;
                var rfc2898 = new Rfc2898DeriveBytes(password, salt, rfc2898KeygenIterations);
                aes.Key = rfc2898.GetBytes(keyStrengthInBytes);
                aes.IV = rfc2898.GetBytes(keyStrengthInBytes);
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(message, 0, message.Length);
                    }

                    cipherText = ms.ToArray();
                }
            }

            return cipherText;
        }

        /// <summary>
        ///     Encriptador de string
        /// </summary>
        /// <param name="message"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="rfc2898KeygenIterations"></param>
        /// <param name="aesKeySizeInBits"></param>
        /// <param name="paddingMode"></param>
        /// <returns></returns>
        public static string EncryptAesString(this string message, string password, byte[] salt,
            int rfc2898KeygenIterations = 100, int aesKeySizeInBits = 128,
            PaddingMode paddingMode = PaddingMode.ISO10126)
        {
            message = message.Trim();
            var rawPlaintext = Encoding.Unicode.GetBytes(message);
            var encrypt = EncryptAes(rawPlaintext, password, salt, rfc2898KeygenIterations, aesKeySizeInBits,
                paddingMode);
            return Convert.ToBase64String(encrypt);
        }

        /// <summary>
        ///     Descriptador
        /// </summary>
        /// <param name="message"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="rfc2898KeygenIterations"></param>
        /// <param name="aesKeySizeInBits"></param>
        /// <param name="paddingMode"></param>
        /// <returns></returns>
        public static byte[] DecryptAes(this byte[] message, string password, byte[] salt,
            int rfc2898KeygenIterations = 100, int aesKeySizeInBits = 128,
            PaddingMode paddingMode = PaddingMode.ISO10126)
        {
            byte[] decryptedMessage = null;

            using (Aes aes = new AesManaged())
            {
                aes.Padding = paddingMode;
                aes.KeySize = aesKeySizeInBits;
                var keyStrengthInBytes = aes.KeySize / 8;
                var rfc2898 = new Rfc2898DeriveBytes(password, salt, rfc2898KeygenIterations);
                aes.Key = rfc2898.GetBytes(keyStrengthInBytes);
                aes.IV = rfc2898.GetBytes(keyStrengthInBytes);


                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(message, 0, message.Length);
                    }

                    decryptedMessage = ms.ToArray();
                }
            }

            return decryptedMessage;
        }

        /// <summary>
        ///     Descriptador de string
        /// </summary>
        /// <param name="encryptedMessage"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="rfc2898KeygenIterations"></param>
        /// <param name="aesKeySizeInBits"></param>
        /// <param name="paddingMode"></param>
        /// <returns></returns>
        public static string DecryptAesString(this string encryptedMessage, string password, byte[] salt,
            int rfc2898KeygenIterations = 100, int aesKeySizeInBits = 128,
            PaddingMode paddingMode = PaddingMode.ISO10126)
        {
            var cipherText = Convert.FromBase64String(encryptedMessage);
            var decrypt = DecryptAes(cipherText, password, salt, rfc2898KeygenIterations, aesKeySizeInBits,
                paddingMode);
            return Encoding.Unicode.GetString(decrypt);
        }
    }
}