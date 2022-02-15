package aladdin.capi.stb.cipher;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.stb.*;
import aladdin.capi.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// ГОСТ 28147-89
///////////////////////////////////////////////////////////////////////////
public final class GOST28147 extends RefObject implements IBlockCipher
{
    // фабрика алгоритмов, область видимости и идентификатор таблицы подстановок
    private final Factory factory; private final SecurityStore scope; private final String sboxOID;

    // конструктор
    public GOST28147(Factory factory, SecurityStore scope, String sboxOID) throws IOException
    {
        // сохранить переданные параметры	
        this.factory = RefObject.addRef(factory); 

        // сохранить переданные параметры	
        this.scope = RefObject.addRef(scope); this.sboxOID = sboxOID; 
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
        return aladdin.capi.gost.keys.GOST28147.INSTANCE; 
    } 
    // размер ключей
    @Override public final int[] keySizes () { return new int[] {32}; } 
    // размер блока
    @Override public final int blockSize() { return 8; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // вернуть режим шифрования ECB
        if (mode instanceof CipherMode.ECB) 
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.GOST28147_ECB), 
                new GOSTSBlock(new ObjectIdentifier(sboxOID))
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 
                
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 
        }
        if (mode instanceof CipherMode.CFB) 
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.GOST28147_CFB), 
                new GOSTParams(new OctetString(((CipherMode.CFB)mode).iv()), 
                    new GOSTSBlock(new ObjectIdentifier(sboxOID))
                )
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 
                
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 
            
            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new aladdin.capi.gost.mode.gost28147.CFB(engine, (CipherMode.CFB)mode); 
            }
        }
        if (mode instanceof CipherMode.CTR) 
        {
            // закодировать параметры алгоритма
            AlgorithmIdentifier parameters = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.GOST28147_CTR), 
                new GOSTParams(new OctetString(((CipherMode.CTR)mode).iv()), 
                    new GOSTSBlock(new ObjectIdentifier(sboxOID))
                )
            );
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(scope, parameters, Cipher.class); 
                
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 

            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new aladdin.capi.gost.mode.gost28147.CTR(engine, (CipherMode.CTR)mode); 
            }
        }
        // режим не поддерживается
        throw new UnsupportedOperationException(); 
    }
}
