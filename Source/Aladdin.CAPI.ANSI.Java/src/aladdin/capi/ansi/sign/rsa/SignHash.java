package aladdin.capi.ansi.sign.rsa;
import aladdin.math.*;
import aladdin.asn1.iso.*;
import aladdin.capi.*; 
import java.io.*;
import java.math.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм подписи RSA
///////////////////////////////////////////////////////////////////////////
public class SignHash extends aladdin.capi.SignHash
{
    // способ кодирования чисел
    protected static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // подписать хэш-значение
    @Override public byte[] sign(aladdin.capi.IPrivateKey privateKey, IRand rand, 
        AlgorithmIdentifier hashAlgorithm, byte[] hash) throws IOException
    {
        // преобразовать тип ключа
        aladdin.capi.ansi.rsa.IPrivateKey rsaPrivateKey = 
            (aladdin.capi.ansi.rsa.IPrivateKey)privateKey; 

        // определить размер модуля в байтах
        int bits = rsaPrivateKey.getModulus().bitLength(); int k = (bits + 7) / 8;  
        
        // закодировать данные
        byte[] encoded = encode(rand, hashAlgorithm, hash, bits); 
        
        // проверить размер данных
        if (encoded.length != k) throw new IllegalStateException(); 
        
        // зашифровать данные
        byte[] encrypted = power(rsaPrivateKey, rand, encoded); 
        
        // проверить размер данных
        if (encrypted.length != k) throw new IllegalStateException(); return encrypted; 
    }
    // закодировать данные
    protected byte[] encode(IRand rand, 
        AlgorithmIdentifier hashAlgorithm, byte[] data, int bits) throws IOException
    {
        // закодировать данные
        return aladdin.capi.ansi.keyx.rsa.Encoding.encode(data, (bits + 7) / 8); 
    }
    // способ возведения в степень
    protected byte[] power(aladdin.capi.ansi.rsa.IPrivateKey privateKey, 
        IRand rand, byte[] hash) throws IOException
    {
        // определить размер модуля в байтах
        int k = (privateKey.getModulus().bitLength() + 7) / 8; 

        // получить значение модуля и экспоненты
        BigInteger modulus  = privateKey.getModulus        (); 
        BigInteger exponent = privateKey.getPrivateExponent(); 

        // закодировать данные
        BigInteger encoded = Convert.toBigInteger(hash, ENDIAN); 
        
        // возвести большое число в степень по модулю
        return Convert.fromBigInteger(
            encoded.modPow(exponent, modulus), ENDIAN, k
        ); 
    }
}
