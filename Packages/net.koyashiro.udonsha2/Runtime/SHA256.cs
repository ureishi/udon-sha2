using System;

namespace Koyashiro.UdonSHA2
{
    public static class SHA256
    {
        private const int MESSAGE_BLOCK_LENGTH = 64;
        public const int DIGEST_LENGTH = 32;

        private const int UINT_SIZE = 4;
        private const int LONG_SIZE = 8;
        private const string initialValues_Base64Str =
            "mC+KQpFEN3HP+8C1pdu16VvCVjnxEfFZpII/ktVeHKuYqgfYAVuDEr6FMSTDfQxV" +
            "dF2+cv6x3oCnBtybdPGbwcFpm+SGR77vxp3BD8yhDCRvLOktqoR0StypsFzaiPl2" +
            "UlE+mG3GMajIJwOwx39Zv/ML4MZHkafVUWPKBmcpKRSFCrcnOCEbLvxtLE0TDThT" +
            "VHMKZbsKanYuycKBhSxykqHov6JLZhqocItLwqNRbMcZ6JLRJAaZ1oU1DvRwoGoQ" +
            "FsGkGQhsNx5Md0gntbywNLMMHDlKqthOT8qcW/NvLmjugo90b2OleBR4yIQIAseM" +
            "+v++kOtsUKT3o/m+8nhxxmfmCWqFrme7cvNuPDr1T6V/Ug5RjGgFm6vZgx8ZzeBb";

        public static byte[] ComputeHash(byte[] buffer)
        {
            var initialValues_Bytes = Convert.FromBase64String(initialValues_Base64Str);

            /*
            var K = new uint[MESSAGE_BLOCK_LENGTH] {
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
            };
            */
            var K = new uint[MESSAGE_BLOCK_LENGTH];
            Buffer.BlockCopy(initialValues_Bytes, 0, K, 0, MESSAGE_BLOCK_LENGTH * UINT_SIZE);

            /*
            var hBuf = new uint[] { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
            */
            var hBuf = new uint[8];
            Buffer.BlockCopy(initialValues_Bytes, MESSAGE_BLOCK_LENGTH * UINT_SIZE, hBuf, 0, 8 * UINT_SIZE);

            var paddedBuffer = Pad(buffer);
            var wb = Divide(paddedBuffer);

            foreach (var w in wb)
            {
                for (var i = 16; i < MESSAGE_BLOCK_LENGTH; i++)
                {
                    w[i] = SmallSigma1(w[i - 2]) + w[i - 7] + SmallSigma0(w[i - 15]) + w[i - 16];
                }

                var a = hBuf[0];
                var b = hBuf[1];
                var c = hBuf[2];
                var d = hBuf[3];
                var e = hBuf[4];
                var f = hBuf[5];
                var g = hBuf[6];
                var h = hBuf[7];

                for (var i = 0; i < MESSAGE_BLOCK_LENGTH; i++)
                {
                    var t1 = h + LargeSigma1(e) + Ch(e, f, g) + K[i] + w[i];
                    var t2 = LargeSigma0(a) + Maj(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t1 + t2;
                }

                hBuf[0] = a + hBuf[0];
                hBuf[1] = b + hBuf[1];
                hBuf[2] = c + hBuf[2];
                hBuf[3] = d + hBuf[3];
                hBuf[4] = e + hBuf[4];
                hBuf[5] = f + hBuf[5];
                hBuf[6] = g + hBuf[6];
                hBuf[7] = h + hBuf[7];
            }

            var digest = new byte[DIGEST_LENGTH];
            Array.Reverse(hBuf);
            Buffer.BlockCopy(hBuf, 0, digest, 0, DIGEST_LENGTH);
            Array.Reverse(digest);

            return digest;
        }

        private static byte[] Pad(byte[] input)
        {
            var inputLength = input.LongLength;
            var bufferLength = (((inputLength + 8L) / MESSAGE_BLOCK_LENGTH) + 1L) * MESSAGE_BLOCK_LENGTH;

            var buffer = new byte[bufferLength];
            Array.Copy(input, buffer, inputLength);
            buffer[inputLength] = 0x80;

            var bitsLength = inputLength * 8L;
            var bitsLength_Bytes = BitConverter.GetBytes(bitsLength);
            Array.Reverse(bitsLength_Bytes);
            Array.Copy(bitsLength_Bytes, 0, buffer, bufferLength - LONG_SIZE, LONG_SIZE);

            return buffer;
        }

        private static uint[][] Divide(byte[] input)
        {
            var inputLength = input.LongLength;
            var mLength = inputLength / MESSAGE_BLOCK_LENGTH;
            var mu = new uint[mLength][];
            for (var i = 0; i < mLength; i++)
            {
                var mu_i = new uint[MESSAGE_BLOCK_LENGTH];
                var ix = i * MESSAGE_BLOCK_LENGTH;
                Array.Reverse(input, ix, MESSAGE_BLOCK_LENGTH);
                Buffer.BlockCopy(input, ix, mu_i, 0, MESSAGE_BLOCK_LENGTH);
                Array.Reverse(mu_i, 0, MESSAGE_BLOCK_LENGTH / UINT_SIZE);
                mu[i] = mu_i;
            }

            return mu;
        }

        private static uint Ch(uint x, uint y, uint z)
        {
            return (x & y) ^ (~x & z);
        }

        private static uint Maj(uint x, uint y, uint z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        private static uint LargeSigma0(uint x)
        {
            return Rotr(x, 2) ^ Rotr(x, 13) ^ Rotr(x, 22);
        }

        private static uint LargeSigma1(uint x)
        {
            return Rotr(x, 6) ^ Rotr(x, 11) ^ Rotr(x, 25);
        }

        private static uint SmallSigma0(uint x)
        {
            return Rotr(x, 7) ^ Rotr(x, 18) ^ Shr(x, 3);
        }

        private static uint SmallSigma1(uint x)
        {
            return Rotr(x, 17) ^ Rotr(x, 19) ^ Shr(x, 10);
        }

        private static uint Rotr(uint x, int n)
        {
            return x << (32 - n) | x >> n;
        }

        private static uint Shr(uint x, int n)
        {
            return x >> n;
        }
    }
}
