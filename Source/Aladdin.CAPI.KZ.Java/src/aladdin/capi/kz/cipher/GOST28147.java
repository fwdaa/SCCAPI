package aladdin.capi.kz.cipher;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.kz.*;
import aladdin.capi.*;
import aladdin.capi.mode.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// ГОСТ 28147-89
///////////////////////////////////////////////////////////////////////////
public final class GOST28147 extends RefObject implements IBlockCipher
{
    // фабрика алгоритмов и область видимости
    private final Factory factory; private final SecurityStore scope; 

    // конструктор
    public GOST28147(Factory factory, SecurityStore scope) throws IOException
    {
        // сохранить переданные параметры	
        this.factory = RefObject.addRef(factory); 

        // сохранить переданные параметры	
        this.scope = RefObject.addRef(scope); 
    } 
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить выделенные ресурсы
        RefObject.release(scope); RefObject.release(factory); super.onClose();
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.gost.keys.GOST.INSTANCE; 
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
            Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, OID.GAMMA_CIPHER_GOST_ECB, parameters, Cipher.class); 
                
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CBC) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = new OctetString(((CipherMode.CBC)mode).iv()); 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, OID.GAMMA_CIPHER_GOST_CBC, parameters, Cipher.class); 
                
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 
            
            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new CBC(engine, (CipherMode.CBC)mode, PaddingMode.ANY); 
            }
        }
        if (mode instanceof CipherMode.CFB) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = new OctetString(((CipherMode.CFB)mode).iv()); 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, OID.GAMMA_CIPHER_GOST_CFB, parameters, Cipher.class); 
                
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 

            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new CFB(engine, (CipherMode.CFB)mode); 
            }
        }
        if (mode instanceof CipherMode.OFB) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = new OctetString(((CipherMode.OFB)mode).iv()); 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, OID.GAMMA_CIPHER_GOST_OFB, parameters, Cipher.class
            ); 
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 

            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new OFB(engine, (CipherMode.OFB)mode); 
            }
        }
        if (mode instanceof CipherMode.CTR) 
        {
            // закодировать параметры алгоритма
            IEncodable parameters = new OctetString(((CipherMode.CTR)mode).iv()); 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, OID.GAMMA_CIPHER_GOST_CNT, parameters, Cipher.class
            ); 
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 

            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new CTR(engine, (CipherMode.CTR)mode); 
            }
        }
        // режим не поддерживается
        throw new UnsupportedOperationException(); 
    }
}
