/*
 * 소스 참조 : https://www.macrosssoftware.com/2019/10/12/decrypting-apple-pay-payment-blob-using-net-part-1-verify-the-signature/
 *           https://github.com/Macross-Software/ApplePayDecryption
 */
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


namespace ApplePay.Extensions
{
    internal static class CertificateExtensions
    {
        public static byte[] ExportPublicKeyInDERFormat(this X509Certificate certificate)
        {
            byte[] algOid = CryptoConfig.EncodeOID(certificate.GetKeyAlgorithm());

            byte[] algParams = certificate.GetKeyAlgorithmParameters();

            byte[] algId = BuildSimpleDERSequence(algOid, algParams);

            byte[] publicKey = WrapAsBitString(certificate.GetPublicKey());

            return BuildSimpleDERSequence(algId, publicKey);
        }

        private static byte[] BuildSimpleDERSequence(params byte[][] values)
        {
            int totalLength = values.Sum(v => v.Length);
            byte[] len = EncodeDERLength(totalLength);
            int offset = 1;

            byte[] seq = new byte[totalLength + len.Length + 1];
            seq[0] = 0x30;

            Buffer.BlockCopy(len, 0, seq, offset, len.Length);
            offset += len.Length;

            foreach (byte[] value in values)
            {
                Buffer.BlockCopy(value, 0, seq, offset, value.Length);
                offset += value.Length;
            }

            return seq;
        }

        private static byte[] WrapAsBitString(byte[] value)
        {
            byte[] len = EncodeDERLength(value.Length + 1);
            byte[] bitString = new byte[value.Length + len.Length + 2];
            bitString[0] = 0x03;
            Buffer.BlockCopy(len, 0, bitString, 1, len.Length);
            bitString[len.Length + 1] = 0x00;
            Buffer.BlockCopy(value, 0, bitString, len.Length + 2, value.Length);
            return bitString;
        }

        private static byte[] EncodeDERLength(int length)
        {
            if (length <= 0x7F)
                return new byte[] { (byte)length };

            if (length <= 0xFF)
                return new byte[] { 0x81, (byte)length };

            if (length <= 0xFFFF)
            {
                return new byte[]
                {
                    0x82,
                    (byte)(length >> 8),
                    (byte)length,
                };
            }

            if (length <= 0xFFFFFF)
            {
                return new byte[]
                {
                    0x83,
                    (byte)(length >> 16),
                    (byte)(length >> 8),
                    (byte)length,
                };
            }

            return new byte[]
            {
                0x84,
                (byte)(length >> 24),
                (byte)(length >> 16),
                (byte)(length >> 8),
                (byte)length,
            };
        }
    }
}
