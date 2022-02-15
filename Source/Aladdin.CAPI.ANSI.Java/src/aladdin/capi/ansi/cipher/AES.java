package aladdin.capi.ansi.cipher;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.ansi.*;
import aladdin.capi.*; 
import aladdin.capi.mode.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования AES
///////////////////////////////////////////////////////////////////////////
public final class AES extends RefObject implements IBlockCipher
{
    // фабрика алгоритмов, область видимости и размер ключа 
    private final Factory factory; private final SecurityStore scope; private final int keyLength;

    // конструктор
    public AES(Factory factory, SecurityStore scope, int keyLength)
    {
        // сохранить переданные параметры	
        this.factory = RefObject.addRef(factory); 
        this.scope   = RefObject.addRef(scope  ); this.keyLength = keyLength; 
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
        return aladdin.capi.ansi.keys.AES.INSTANCE; 
    } 
    // размер ключей
    @Override public final int[] keySizes () { return new int[] {keyLength}; } 
    // размер блока
    @Override public final int blockSize() { return 16; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
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
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(oid), Null.INSTANCE
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 

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
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(oid), 
                new OctetString(((CipherMode.CBC)mode).iv())
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 

            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
            
            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new CBC(engine, (CipherMode.CBC)mode, PaddingMode.ANY); 
            }
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
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(oid), new FBParameter(
                    new OctetString(((CipherMode.OFB)mode).iv()), new aladdin.asn1.Integer(64)
                )
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 

            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
            
            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new OFB(engine, (CipherMode.OFB)mode); 
            }
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
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(oid), new FBParameter(
                    new OctetString(((CipherMode.CFB)mode).iv()), new aladdin.asn1.Integer(64)
                )
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 

            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 

            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new CFB(engine, (CipherMode.CFB)mode); 
            }
        }
        // режим не поддерживается
        throw new UnsupportedOperationException();
    }
}
