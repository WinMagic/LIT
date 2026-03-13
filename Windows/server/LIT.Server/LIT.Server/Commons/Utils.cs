using System.Security.Cryptography;

namespace LIT.ServerMVC.Commons
{
    public static class Utils
    {
        //Generating password
        private const int DefaultLength = 16;
        private static readonly char[] Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
        private static readonly char[] Lowercase = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
        private static readonly char[] Digits = "0123456789".ToCharArray();
        private static readonly char[] Symbols = "!@#$%^&*_-+=[]{}:,.?".ToCharArray();

        //Password hashing
        private const int Iterations = 120_000;
        private const int SaltSize = 16;
        private const int KeySize = 32;



        public static string Generate(int length = DefaultLength, bool requireAllCategories = true)
        {
            if (length < 8)
                throw new ArgumentException("Password length should be at least 8.", nameof(length));

            var all = Uppercase.Concat(Lowercase).Concat(Digits).Concat(Symbols).ToArray();
            var pwd = new char[length];

            int idx = 0;
            if (requireAllCategories)
            {
                pwd[idx++] = GetRandomChar(Uppercase);
                pwd[idx++] = GetRandomChar(Lowercase);
                pwd[idx++] = GetRandomChar(Digits);
                pwd[idx++] = GetRandomChar(Symbols);
            }

            for (; idx < length; idx++)
                pwd[idx] = GetRandomChar(all);

            Shuffle(pwd);

            return new string(pwd);
        }

        private static char GetRandomChar(char[] chars)
        {
            var i = RandomNumberGenerator.GetInt32(chars.Length);
            return chars[i];
        }

        private static void Shuffle(char[] array)
        {
            for (int i = array.Length - 1; i > 0; i--)
            {
                int j = RandomNumberGenerator.GetInt32(i + 1);
                (array[i], array[j]) = (array[j], array[i]);
            }
        }

        public static string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);

            byte[] subkey = Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                Iterations,
                HashAlgorithmName.SHA256,
                KeySize
            );

            // Store: iterations:salt:subkey (Base64)
            return $"{Iterations}:{Convert.ToBase64String(salt)}:{Convert.ToBase64String(subkey)}";
        }

        public static bool VerifyHashedPassword(string hashed, string providedPassword)
        {
            if (string.IsNullOrWhiteSpace(hashed))
                return false;

            var parts = hashed.Split(':', 3);
            if (parts.Length != 3)
                return false;

            if (!int.TryParse(parts[0], out int iterations))
                return false;

            byte[] salt;
            byte[] expectedSubkey;
            try
            {
                salt = Convert.FromBase64String(parts[1]);
                expectedSubkey = Convert.FromBase64String(parts[2]);
            }
            catch
            {
                return false;
            }

            byte[] actualSubkey = Rfc2898DeriveBytes.Pbkdf2(
                providedPassword,
                salt,
                iterations,
                HashAlgorithmName.SHA256,
                expectedSubkey.Length
            );

            return CryptographicOperations.FixedTimeEquals(actualSubkey, expectedSubkey);
        }

    }
}
