/*
 * 소스 참조 : https://www.macrosssoftware.com/2019/10/12/decrypting-apple-pay-payment-blob-using-net-part-1-verify-the-signature/
 *           https://github.com/Macross-Software/ApplePayDecryption
 */
using System;
using System.Linq;

namespace ApplePay.Extensions
{
    internal static class ConversionExtensions
    {
        /// <summary>
        /// Hex String -> Bytes 변환
        /// </summary>
        /// <param name="hexString"></param>
        /// <returns></returns>
        public static byte[] ToByteArray(this string hexString)
        {
            return Enumerable.Range(0, hexString.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hexString.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
