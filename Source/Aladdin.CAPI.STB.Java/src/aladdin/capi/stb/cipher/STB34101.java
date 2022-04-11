package aladdin.capi.stb.cipher;
import aladdin.*; 
import aladdin.asn1.*;
import aladdin.asn1.stb.*;
import aladdin.capi.*; 
import java.io.*; 
import java.security.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования BELT
///////////////////////////////////////////////////////////////////////////
public class STB34101 extends RefObject implements IBlockCipher
{
    // фабрика алгоритмов, область видимости и размер ключа
    private final Factory factory; private final SecurityStore scope; 

    // конструктор
    public STB34101(Factory factory, SecurityStore scope)
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
        return new aladdin.capi.stb.keys.STB34101(new int[] {16, 24, 32}); 
    } 
    // размер блока
    @Override public final int blockSize() { return 16; } 
        
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // в зависимости от режима
        if (mode instanceof CipherMode.ECB) return new BlockMode(this, mode); 
        if (mode instanceof CipherMode.CBC) return new BlockMode(this, mode); 
        if (mode instanceof CipherMode.CFB) return new BlockMode(this, mode); 
        if (mode instanceof CipherMode.CTR) return new BlockMode(this, mode); 
            
        // режим не поддерживается
        throw new UnsupportedOperationException();
    }
    // получить режим шифрования
     public Cipher createBlockMode(CipherMode mode, int keyLength) throws IOException
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
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, oid, Null.INSTANCE, Cipher.class
            ); 
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
            IEncodable parameters = new OctetString(((CipherMode.CBC)mode).iv()); 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, oid, parameters, Cipher.class
            ); 
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 

            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new aladdin.capi.stb.mode.stb34101.CBC(engine, (CipherMode.CBC)mode); 
            }
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
            IEncodable parameters = new OctetString(((CipherMode.CFB)mode).iv()); 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, oid, parameters, Cipher.class
            ); 
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 
            
            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new aladdin.capi.stb.mode.stb34101.CFB(engine, (CipherMode.CFB)mode); 
            }
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
            IEncodable parameters = new OctetString(((CipherMode.CTR)mode).iv()); 
            
            // получить алгоритм шифрования
            Cipher cipher = (Cipher)factory.createAlgorithm(
                scope, oid, parameters, Cipher.class
            ); 
            // проверить наличие алгоритма
            if (cipher != null) return cipher; 

            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new aladdin.capi.stb.mode.stb34101.CTR(engine, (CipherMode.CTR)mode); 
            }
        }
        // режим не поддерживается
        throw new UnsupportedOperationException(); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования с неизвестным заранее размером ключа
    ///////////////////////////////////////////////////////////////////////////
    private static class BlockMode extends aladdin.capi.Cipher
    {
        // блочный алгоритм шифрования и режим
        private final STB34101 blockCipher; private final CipherMode mode; 
        
        // конструктор
        public BlockMode(STB34101 blockCipher, CipherMode mode)
        {
            // сохранить переданные параметры
            this.blockCipher = RefObject.addRef(blockCipher); this.mode = mode; 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException
        {
            // освободить выделенные ресурсы
            RefObject.release(blockCipher); super.onClose();
        }
        // тип ключа
        @Override public final SecretKeyFactory keyFactory() { return blockCipher.keyFactory(); }
        // размер блока
        @Override public final int blockSize() { return blockCipher.blockSize(); }
        
        // режим алгоритма
        @Override public final CipherMode mode() { return mode; } 
    
        // алгоритм зашифрования данных
        @Override public Transform createEncryption(ISecretKey key, PaddingMode padding) 
            throws IOException, InvalidKeyException
        {
            // создать блочный алгоритм шифрования
            try (Cipher blockMode = blockCipher.createBlockMode(mode, key.length()))
            {
                // создать преобразование зашифрования
                return blockMode.createEncryption(key, padding); 
            }
        }
        // алгоритм расшифрования данных
        @Override public Transform createDecryption(ISecretKey key, PaddingMode padding) 
            throws IOException, InvalidKeyException 
        {
            // создать блочный алгоритм шифрования
            try (Cipher blockMode = blockCipher.createBlockMode(mode, key.length()))
            {
                // создать преобразование расшифрования
                return blockMode.createDecryption(key, padding); 
            }
        }
    }
    
}
