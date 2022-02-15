package aladdin.capi.ansi.cipher;
import aladdin.*; 
import aladdin.math.*;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.ansi.*;
import aladdin.capi.*; 
import aladdin.capi.mode.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования DES
///////////////////////////////////////////////////////////////////////////
public final class DES extends RefObject implements IBlockCipher
{
    // способ кодирования чисел
    private static final Endian ENDIAN = Endian.BIG_ENDIAN; 
    
    // фабрика алгоритмов и область видимости
    private final Factory factory; private final SecurityStore scope; 

    // конструктор
    public DES(Factory factory, SecurityStore scope) 
    {
        // сохранить переданные параметры	
        this.factory = RefObject.addRef(factory); this.scope = RefObject.addRef(scope);
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
        return aladdin.capi.ansi.keys.DES.INSTANCE; 
    } 
    // размер ключей
    @Override public final int[] keySizes () { return new int[] {8}; } 
    // размер блока
    @Override public final int blockSize() { return 8; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // в зависимости от режима
        if (mode instanceof CipherMode.ECB) 
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.SSIG_DES_ECB), Null.INSTANCE
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 

            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CBC) 
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.SSIG_DES_CBC), 
                new OctetString(((CipherMode.CBC)mode).iv())
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 

            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 
            
            // получить алгоритм шифрования блока
            try (Cipher engine = createBlockMode(new CipherMode.ECB()))
            {
                // вернуть режим алгоритма
                return new CBC(engine, (CipherMode.CBC)mode, PaddingMode.ANY); 
            }
        }
        // в зависимости от режима
        if (mode instanceof CipherMode.OFB) 
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.SSIG_DES_OFB), new FBParameter(
                    new OctetString(((CipherMode.OFB)mode).iv()), new aladdin.asn1.Integer(64)
                )
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 

            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 

            // получить алгоритм шифрования блока
            try (Cipher engine = createBlockMode(new CipherMode.ECB()))
            {
                // вернуть режим алгоритма
                return new OFB(engine, (CipherMode.OFB)mode); 
            }
        }
        // в зависимости от режима
        if (mode instanceof CipherMode.CFB) 
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.SSIG_DES_CFB), new FBParameter(
                    new OctetString(((CipherMode.CFB)mode).iv()), new aladdin.asn1.Integer(64)
                )
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 
                
            // вернуть алгоритм шифрования
            if (cipher != null) return cipher; 

            // получить алгоритм шифрования блока
            try (Cipher engine = createBlockMode(new CipherMode.ECB()))
            {
                // вернуть режим алгоритма
                return new CFB(engine, (CipherMode.CFB)mode); 
            }
        }
        // режим не поддерживается
        throw new UnsupportedOperationException();
    }
}
