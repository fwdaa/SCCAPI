package aladdin.capi.ansi.pkcs11.x957;
import aladdin.math.*; 
import aladdin.asn1.Integer;
import aladdin.asn1.ansi.x957.*; 
import aladdin.util.*; 
import java.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Кодирование подписи DSA
///////////////////////////////////////////////////////////////////////////////
public class Encoding 
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // закодировать подпись
    public static byte[] encodeSignature(
        aladdin.capi.ansi.x957.IParameters parameters, DssSigValue signature)
    {
        // определить параметр алгоритма
        int bytesR = (parameters.getQ().bitLength() + 7) / 8; 

        // закодировать параметры R и S
        byte[] r = Convert.fromBigInteger(signature.r().value(), ENDIAN, bytesR); 
        byte[] s = Convert.fromBigInteger(signature.s().value(), ENDIAN, bytesR); 

        // объединить параметры
        return Array.concat(r, s); 
    }
    // раскодировать подпись
    public static DssSigValue decodeSignature(
        aladdin.capi.ansi.x957.IParameters parameters, byte[] signature) throws IOException
    {
        // определить параметр алгоритма
        int bytesR = (parameters.getQ().bitLength() + 7) / 8; 

        // проверить размер подписи
        int bytesS = signature.length - bytesR; if (bytesS <= 0) throw new IOException();

        // раскодировать параметры R и S
        BigInteger r = Convert.toBigInteger(signature,      0, bytesR, ENDIAN); 
        BigInteger s = Convert.toBigInteger(signature, bytesR, bytesS, ENDIAN); 

        // закодировать подпись
        return new DssSigValue(new Integer(r), new Integer(s)); 
    }
}
