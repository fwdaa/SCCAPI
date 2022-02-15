package aladdin.capi.ansi.cipher;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.ansi.*;
import aladdin.capi.*; 
import aladdin.capi.mode.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования TDES
///////////////////////////////////////////////////////////////////////////
public final class TDES extends RefObject implements IBlockCipher
{
    // фабрика алгоритмов, область видимости и размер ключа
    private final Factory factory; private final SecurityStore scope; private final int keyLength; 

    // конструктор
    public TDES(Factory factory, SecurityStore scope, int keyLength) 
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
        return aladdin.capi.ansi.keys.TDES.INSTANCE; 
    } 
    // размер ключей
    @Override public final int[] keySizes () { return new int[] {keyLength}; } 
    // размер блока
    @Override public final int blockSize() { return 8; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        if (keyLength == 24 && mode instanceof CipherMode.ECB)
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.TT_TDES192_ECB), Null.INSTANCE
            );
            // получить алгоритм шифрования
            try (Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, parameters, Cipher.class)) 
            {
                // изменить режим дополнения
                if (cipher != null) return new BlockMode.ConvertPadding(cipher, PaddingMode.ANY);   
            }
        }
        if (keyLength == 24 && mode instanceof CipherMode.CBC)
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.TT_TDES192_CBC), 
                new OctetString(((CipherMode.CBC)mode).iv())
            );
            // получить алгоритм шифрования
            try (Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class)) 
            {
                // изменить режим дополнения
                if (cipher != null) return new BlockMode.ConvertPadding(cipher, PaddingMode.ANY); 
            }
        }
        // в зависимости от режима
        if (mode instanceof CipherMode.ECB) 
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.SSIG_TDES_ECB), Null.INSTANCE
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 
            
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CBC) 
        {
            // получить алгоритм шифрования блока
            try (Cipher engine = createBlockMode(new CipherMode.ECB()))
            {
                // вернуть режим шифрования
                return new CBC(engine, (CipherMode.CBC)mode, PaddingMode.ANY); 
            }
        }
        // в зависимости от режима
        if (mode instanceof CipherMode.OFB) 
        {
            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new OFB(engine, (CipherMode.OFB)mode); 
            }
        }
        // в зависимости от режима
        if (mode instanceof CipherMode.CFB) 
        {
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
