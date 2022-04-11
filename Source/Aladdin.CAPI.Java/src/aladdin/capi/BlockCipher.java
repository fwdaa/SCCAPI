package aladdin.capi;
import aladdin.*; 
import aladdin.capi.mode.*;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования
///////////////////////////////////////////////////////////////////////////////
public class BlockCipher extends RefObject implements IBlockCipher
{
    // конструктор
    public BlockCipher(Cipher engine) 
      
        // сохранить переданные параметры
        { this.engine = RefObject.addRef(engine); } private final Cipher engine;
    
    // деструктор
    @Override protected void onClose() throws IOException
    { 
        // освободить выделенные ресурсы
        RefObject.release(engine); super.onClose();
    } 
    // тип ключа
	@Override public SecretKeyFactory keyFactory() { return engine.keyFactory(); } 
    
    // размер блока
	@Override public int blockSize() { return engine.blockSize(); } 
    
    // алгоритм шифрования блока
    protected final Cipher engine() { return engine; }
    
    // создать режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // вернуть режим шифрования ECB
        if (mode instanceof CipherMode.ECB) return new ECB(engine(), PaddingMode.ANY);  
        if (mode instanceof CipherMode.CBC) 
        {
            // вернуть режим шифрования CBC
            return new CBC(engine(), (CipherMode.CBC)mode, PaddingMode.ANY);  
        }
        if (mode instanceof CipherMode.CFB) 
        {
            // вернуть режим шифрования CFB
            return new CFB(engine(), (CipherMode.CFB)mode);  
        }
        if (mode instanceof CipherMode.OFB) 
        {
            // вернуть режим шифрования CFB
            return new OFB(engine(), (CipherMode.OFB)mode);  
        }
        if (mode instanceof CipherMode.CTR) 
        {
            // вернуть режим шифрования CFB
            return new CTR(engine(), (CipherMode.CTR)mode);  
        }
        // при ошибке выбросить исключение
        throw new UnsupportedOperationException(); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тесты известного ответа
    ///////////////////////////////////////////////////////////////////////////
    public static void knownTestECB(IBlockCipher blockCipher, PaddingMode padding, 
        byte[] key, byte[] plaintext, byte[] ciphertext) throws Exception
    {
        // создать режим ECB
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.ECB()))
        {
            // выполнить тест известного ответа
            Cipher.knownTest(cipher, padding, key, plaintext, ciphertext);
        }
    }
    public static void knownTestCBC(IBlockCipher blockCipher, 
        byte[] iv, PaddingMode padding, 
        byte[] key, byte[] plaintext, byte[] ciphertext) throws Exception
    {
        // создать режим ECB
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.CBC(iv, iv.length)))
        {
            // выполнить тест известного ответа
            Cipher.knownTest(cipher, padding, key, plaintext, ciphertext);
        }
    }
    public static void knownTestOFB(IBlockCipher blockCipher, 
        byte[] iv, byte[] key, byte[] plaintext, byte[] ciphertext) throws Exception
    {
        // создать режим ECB
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.OFB(iv, iv.length)))
        {
            // выполнить тест известного ответа
            Cipher.knownTest(cipher, PaddingMode.NONE, key, plaintext, ciphertext);
        }
    }
    public static void knownTestCFB(IBlockCipher blockCipher, 
        byte[] iv, byte[] key, byte[] plaintext, byte[] ciphertext) throws Exception
    {
        // создать режим ECB
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.CFB(iv, iv.length)))
        {
            // выполнить тест известного ответа
            Cipher.knownTest(cipher, PaddingMode.NONE, key, plaintext, ciphertext);
        }
    }
    public static void knownTestCTR(IBlockCipher blockCipher, 
        byte[] iv, byte[] key, byte[] plaintext, byte[] ciphertext) throws Exception
    {
        // создать режим ECB
        try (Cipher cipher = blockCipher.createBlockMode(new CipherMode.CTR(iv, iv.length)))
        {
            // выполнить тест известного ответа
            Cipher.knownTest(cipher, PaddingMode.NONE, key, plaintext, ciphertext);
        }
    }
}
