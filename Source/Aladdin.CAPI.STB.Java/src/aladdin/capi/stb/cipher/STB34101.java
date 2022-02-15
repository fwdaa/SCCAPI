package aladdin.capi.stb.cipher;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.stb.*;
import aladdin.capi.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования BELT
///////////////////////////////////////////////////////////////////////////
public class STB34101 extends RefObject implements IBlockCipher
{
    // фабрика алгоритмов, область видимости и размер ключа
    private final Factory factory; private final SecurityStore scope; private final int keyLength; 

    // конструктор
    public STB34101(Factory factory, SecurityStore scope, int keyLength)
    {
        // сохранить переданные параметры	
        this.factory = RefObject.addRef(factory); 

        // сохранить переданные параметры	
        this.scope = RefObject.addRef(scope); this.keyLength = keyLength; 
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
        return aladdin.capi.stb.keys.STB34101.INSTANCE; 
    } 
    // размер ключей
    @Override public final int[] keySizes () { return new int[] {keyLength}; } 
    // размер блока
    @Override public final int blockSize() { return 16; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // вернуть режим шифрования ECB
        if (mode instanceof CipherMode.ECB) 
        {
            // указать идентификатор алгоритма
            String oid = OID.STB34101_BELT_ECB_256; switch (keyLength)
            {
            case 24: oid = OID.STB34101_BELT_ECB_192; break; 
            case 16: oid = OID.STB34101_BELT_ECB_128; break; 
            }
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(oid), Null.INSTANCE
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 
                
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CBC) 
        {
            // указать идентификатор алгоритма
            String oid = OID.STB34101_BELT_CBC_256; switch (keyLength)
            {
            case 24: oid = OID.STB34101_BELT_CBC_192; break; 
            case 16: oid = OID.STB34101_BELT_CBC_128; break; 
            }
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(oid), new OctetString(((CipherMode.CBC)mode).iv())
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 
                
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CFB) 
        {
            // указать идентификатор алгоритма
            String oid = OID.STB34101_BELT_CFB_256; switch (keyLength)
            {
            case 24: oid = OID.STB34101_BELT_CFB_192; break; 
            case 16: oid = OID.STB34101_BELT_CFB_128; break; 
            }
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(oid), new OctetString(((CipherMode.CFB)mode).iv())
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 
                
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CTR) 
        {
            // указать идентификатор алгоритма
            String oid = OID.STB34101_BELT_CTR_256; switch (keyLength)
            {
            case 24: oid = OID.STB34101_BELT_CTR_192; break; 
            case 16: oid = OID.STB34101_BELT_CTR_128; break; 
            }
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(oid), new OctetString(((CipherMode.CTR)mode).iv())
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 
                
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 
        }
        // режим не поддерживается
        throw new UnsupportedOperationException(); 
    }
}
