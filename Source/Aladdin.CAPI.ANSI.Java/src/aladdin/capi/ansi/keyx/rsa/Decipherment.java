package aladdin.capi.ansi.keyx.rsa;
import aladdin.math.*;
import java.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм расшифрования RSA
///////////////////////////////////////////////////////////////////////////
public class Decipherment extends aladdin.capi.Decipherment
{
    // способ кодирования чисел
    protected static final Endian ENDIAN = Endian.BIG_ENDIAN; 

    // расшифровать данные
    @Override public byte[] decrypt(
        aladdin.capi.IPrivateKey privateKey, byte[] data) throws IOException
    {
        // преобразовать тип ключа
        aladdin.capi.ansi.rsa.IPrivateKey rsaPrivateKey = 
            (aladdin.capi.ansi.rsa.IPrivateKey)privateKey;
        
        // вычислить максимальный размер данных
        int bits = rsaPrivateKey.getModulus().bitLength(); int k = (bits + 7) / 8; 

        // проверить размер данных
        if (data.length != k) throw new IOException(); 
            
        // расшифровать данные
        byte[] encoded = power(rsaPrivateKey, data); 
        
        // проверить размер данных
        if (encoded.length != k) throw new IllegalStateException(); 
        
        // раскодировать данные
        return decode(encoded, bits);         
    }
    // раскодировать данные
    protected byte[] decode(byte[] encoded, int bits) throws IOException { return encoded; }
    
    // способ возведения в степень
    protected byte[] power(
        aladdin.capi.ansi.rsa.IPrivateKey privateKey, byte[] data) throws IOException
    {
        // определить размер модуля в байтах
        int k = (privateKey.getModulus().bitLength() + 7) / 8; 

        // получить значение модуля и экспоненты
        BigInteger modulus  = privateKey.getModulus        (); 
        BigInteger exponent = privateKey.getPrivateExponent(); 

        // раскодировать данные
        BigInteger decoded = Convert.toBigInteger(data, ENDIAN); 
                
        // возвести большое число в степень по модулю
        return Convert.fromBigInteger(
            decoded.modPow(exponent, modulus), ENDIAN, k
        ); 
    }
}
