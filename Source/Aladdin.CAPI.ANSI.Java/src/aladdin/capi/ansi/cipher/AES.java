package aladdin.capi.ansi.cipher;
import aladdin.asn1.*;
import aladdin.asn1.ansi.*;
import aladdin.capi.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования AES
///////////////////////////////////////////////////////////////////////////
public final class AES extends BlockCipher
{
    // конструктор
    public AES(Factory factory, SecurityStore scope) { super(factory, scope); }
    
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return new aladdin.capi.ansi.keys.AES(new int[] {16, 24, 32}); 
    } 
    // размер блока
    @Override public final int blockSize() { return 16; } 
        
    // получить режим шифрования
    @Override protected Cipher createBlockMode(
        CipherMode mode, int keyLength) throws IOException
    {
        // в зависимости от режима
        if (mode instanceof CipherMode.ECB) 
        {
            // указать идентификатор алгоритма
            String oid = OID.NIST_AES256_ECB; switch (keyLength)
            {
            case 24: oid = OID.NIST_AES192_ECB; break; 
            case 16: oid = OID.NIST_AES128_ECB; break; 
            }
            // закодировать параметры алгоритма
            IEncodable parameters = Null.INSTANCE; 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), oid, parameters, Cipher.class
            ); 
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CBC) 
        {
            // указать идентификатор алгоритма
            String oid = OID.NIST_AES256_CBC; switch (keyLength)
            {
            case 24: oid = OID.NIST_AES192_CBC; break; 
            case 16: oid = OID.NIST_AES128_CBC; break; 
            }
            // закодировать параметры алгоритма
            IEncodable parameters = new OctetString(((CipherMode.CBC)mode).iv()); 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), oid, parameters, Cipher.class
            ); 
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.OFB) 
        {
            // указать идентификатор алгоритма
            String oid = OID.NIST_AES256_OFB; switch (keyLength)
            {
            case 24: oid = OID.NIST_AES192_OFB; break; 
            case 16: oid = OID.NIST_AES128_OFB; break; 
            }
            // закодировать параметры алгоритма
            IEncodable parameters = new FBParameter(
                new OctetString(((CipherMode.OFB)mode).iv()), 
                new aladdin.asn1.Integer(64)
            ); 
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), oid, parameters, Cipher.class
            ); 
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CFB) 
        {
            // указать идентификатор алгоритма
            String oid = OID.NIST_AES256_CFB; switch (keyLength)
            {
            case 24: oid = OID.NIST_AES192_CFB; break; 
            case 16: oid = OID.NIST_AES128_CFB; break; 
            }
            // закодировать параметры алгоритма
            IEncodable parameters = new FBParameter(
                new OctetString(((CipherMode.CFB)mode).iv()), 
                new aladdin.asn1.Integer(64)
            ); 
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), oid, parameters, Cipher.class
            ); 
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        // вызвать базовую функцию
        return super.createBlockMode(mode, keyLength); 
    }     
}
