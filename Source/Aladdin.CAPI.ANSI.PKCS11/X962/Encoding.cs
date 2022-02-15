using System;
using System.IO;

namespace Aladdin.CAPI.ANSI.PKCS11.X962
{
    ///////////////////////////////////////////////////////////////////////////////
    // Кодирование подписи ECDSA
    ///////////////////////////////////////////////////////////////////////////////
    public static class Encoding 
    {
        // способ кодирования чисел
        private const Math.Endian Endian = Math.Endian.BigEndian; 
    
        // закодировать подпись
        public static byte[] EncodeSignature(
            ANSI.X962.IParameters parameters, ASN1.ANSI.X962.ECDSASigValue signature)
        {
            // определить параметр алгоритма
            int bytesR = parameters.Order.BitLength / 8; 

            // закодировать параметры R и S
            byte[] r = Math.Convert.FromBigInteger(signature.R.Value, Endian, bytesR); 
            byte[] s = Math.Convert.FromBigInteger(signature.S.Value, Endian, bytesR); 

            // объединить параметры
            return Arrays.Concat(r, s); 
        }
        // раскодировать подпись
        public static ASN1.ANSI.X962.ECDSASigValue DecodeSignature(
            ANSI.X962.IParameters parameters, byte[] signature) 
        {
            // определить параметр алгоритма
            int bytesR = parameters.Order.BitLength / 8; int bytesS = signature.Length - bytesR; 
        
            // проверить размер подписи
            if (bytesS <= 0) throw new InvalidDataException();

            // раскодировать параметры R и S
            Math.BigInteger r = Math.Convert.ToBigInteger(signature,      0, bytesR, Endian); 
            Math.BigInteger s = Math.Convert.ToBigInteger(signature, bytesR, bytesS, Endian); 

            // закодировать подпись
            return new ASN1.ANSI.X962.ECDSASigValue(
                new ASN1.Integer(r), new ASN1.Integer(s), null, null
            ); 
        }
    }
}
