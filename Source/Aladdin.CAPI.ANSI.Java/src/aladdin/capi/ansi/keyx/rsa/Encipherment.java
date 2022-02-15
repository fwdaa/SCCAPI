package aladdin.capi.ansi.keyx.rsa;
import aladdin.math.*;
import aladdin.capi.*;
import java.math.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм зашифрования RSA
///////////////////////////////////////////////////////////////////////////
public class Encipherment extends aladdin.capi.Encipherment
{
    // способ кодирования чисел
    protected static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // зашифровать данные
    @Override public byte[] encrypt(aladdin.capi.IPublicKey publicKey, 
        IRand rand, byte[] data) throws IOException
    {
        // преобразовать тип ключа
        aladdin.capi.ansi.rsa.IPublicKey rsaPublicKey = 
            (aladdin.capi.ansi.rsa.IPublicKey)publicKey;  

        // определить размер модуля в байтах
        int bits = rsaPublicKey.getModulus().bitLength(); int k = (bits + 7) / 8; 
        
        // закодировать данные
        byte[] encoded = encode(rand, data, bits); 
        
        // проверить размер данных
        if (encoded.length != k) throw new IllegalStateException(); 
        
        // зашифровать данные
        byte[] encrypted = power(rsaPublicKey, encoded); 
        
        // проверить размер данных
        if (encrypted.length != k) throw new IllegalStateException(); return encrypted; 
    }
    // закодировать данные
    protected byte[] encode(IRand rand, byte[] data, int bits) throws IOException
    {
        // закодировать данные
        return Encoding.encode(data, (bits + 7) / 8); 
    }
    // способ возведения в степень
    protected byte[] power(
        aladdin.capi.ansi.rsa.IPublicKey publicKey, byte[] data) throws IOException
    {
        // определить размер модуля в байтах
        int k = (publicKey.getModulus().bitLength() + 7) / 8; 

        // получить значение модуля и экспоненты
        BigInteger modulus  = publicKey.getModulus       (); 
        BigInteger exponent = publicKey.getPublicExponent(); 

        // закодировать данные
        BigInteger encoded = Convert.toBigInteger(data, ENDIAN); 
        
        // возвести большое число в степень по модулю
        return Convert.fromBigInteger(
            encoded.modPow(exponent, modulus), ENDIAN, k
        ); 
    }
}
