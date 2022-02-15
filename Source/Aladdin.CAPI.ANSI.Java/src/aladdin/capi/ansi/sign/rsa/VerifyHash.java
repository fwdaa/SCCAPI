package aladdin.capi.ansi.sign.rsa;
import aladdin.math.*;
import aladdin.asn1.iso.*;
import java.security.*; 
import java.math.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм проверки подписи RSA
///////////////////////////////////////////////////////////////////////////
public class VerifyHash extends aladdin.capi.VerifyHash
{
    // способ кодирования чисел
    protected static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // проверить подпись хэш-значения
    @Override public void verify(aladdin.capi.IPublicKey publicKey, 
        AlgorithmIdentifier hashAlgorithm, byte[] hash, 
        byte[] signature) throws SignatureException, IOException
    {
        // преобразовать тип ключа
        aladdin.capi.ansi.rsa.IPublicKey rsaPublicKey = 
            (aladdin.capi.ansi.rsa.IPublicKey)publicKey; 

        // вычислить максимальный размер данных
        int bits = rsaPublicKey.getModulus().bitLength(); int k = (bits + 7) / 8; 

        // проверить размер данных
        if (signature.length != k) throw new IOException(); 
            
        // расшифровать данные
        byte[] encoded = power(rsaPublicKey, signature); 
        
        // проверить размер данных
        if (encoded.length != k) throw new IllegalStateException(); 
        
        // проверить подпись
        check(encoded, bits, hashAlgorithm, hash);         
    }
    // проверить подпись
    protected void check(byte[] encoded, int bits, 
        AlgorithmIdentifier hashAlgorithm, byte[] hash) throws IOException, SignatureException
    {
        // закодировать данные
        byte[] check = aladdin.capi.ansi.keyx.rsa.Encoding.encode(hash, encoded.length); 
        
        // проверить совпадение значений
        if (!Arrays.equals(check, encoded)) throw new SignatureException();  
    }
    // способ возведения в степень
    protected byte[] power(aladdin.capi.ansi.rsa.IPublicKey publicKey, 
        byte[] signature) throws IOException
    {
        // определить размер модуля в байтах
        int k = (publicKey.getModulus().bitLength() + 7) / 8; 

        // получить значение модуля и экспоненты
        BigInteger modulus  = publicKey.getModulus       (); 
        BigInteger exponent = publicKey.getPublicExponent(); 

        // закодировать данные
        BigInteger encoded = Convert.toBigInteger(signature, ENDIAN); 
        
        // возвести большое число в степень по модулю
        return Convert.fromBigInteger(
            encoded.modPow(exponent, modulus), ENDIAN, k
        ); 
    }
}
