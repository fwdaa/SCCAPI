package aladdin.capi.ansi.cipher;
import aladdin.asn1.*;
import aladdin.asn1.ansi.*;
import aladdin.capi.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования DES
///////////////////////////////////////////////////////////////////////////
public final class DES extends BlockCipher
{
    // конструктор
    public DES(Factory factory, SecurityStore scope) { super(factory, scope); } 
    
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.ansi.keys.DES.INSTANCE; 
    } 
    // размер блока
    @Override public final int blockSize() { return 8; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // в зависимости от режима
        if (mode instanceof CipherMode.ECB) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = Null.INSTANCE; 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), OID.SSIG_DES_ECB, parameters, Cipher.class
            ); 
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CBC) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = new OctetString(((CipherMode.CBC)mode).iv()); 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), OID.SSIG_DES_CBC, parameters, Cipher.class
            ); 
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        // в зависимости от режима
        if (mode instanceof CipherMode.OFB) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = new FBParameter(
                new OctetString(((CipherMode.OFB)mode).iv()), 
                new aladdin.asn1.Integer(64)
            ); 
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), OID.SSIG_DES_OFB, parameters, Cipher.class
            ); 
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        // в зависимости от режима
        if (mode instanceof CipherMode.CFB) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = new FBParameter(
                new OctetString(((CipherMode.CFB)mode).iv()), 
                new aladdin.asn1.Integer(64)
            ); 
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory().createAlgorithm(
                scope(), OID.SSIG_DES_CFB, parameters, Cipher.class); 
                
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        // вызвать базовую функцию
        return createBlockMode(mode, 8); 
    }
}
