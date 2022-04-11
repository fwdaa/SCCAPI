package aladdin.capi.ansi.cipher;
import aladdin.*;
import aladdin.capi.*;
import aladdin.capi.mode.*;
import java.io.*;
import java.security.*;

///////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования
///////////////////////////////////////////////////////////////////////////
public abstract class BlockCipher extends RefObject implements IBlockCipher
{
    // фабрика алгоритмов и область видимости
    private final Factory factory; private final SecurityStore scope; 

    // конструктор
    public BlockCipher(aladdin.capi.Factory factory, SecurityStore scope) 
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
    // фабрика алгоритмов и область видимости
    protected final Factory       factory() { return factory; }
    protected final SecurityStore scope  () { return scope;   }
    
    // тип ключа
    @Override public abstract SecretKeyFactory keyFactory();  
    
    // размер блока
    @Override public abstract int blockSize(); 
        
    // получить режим шифрования
    protected Cipher createBlockMode(CipherMode mode, int keyLength) throws IOException
    {
        // в зависиморсти от режима
        if (mode instanceof CipherMode.CBC) 
        {
            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new CBC(engine, (CipherMode.CBC)mode, PaddingMode.ANY); 
            }
        }
        // в зависиморсти от режима
        if (mode instanceof CipherMode.OFB) 
        {
            // получить алгоритм шифрования
            try (Cipher engine = createBlockMode(new CipherMode.ECB())) 
            {
                // вернуть режим шифрования
                return new OFB(engine, (CipherMode.OFB)mode); 
            }
        }
        // в зависиморсти от режима
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
    // получить режим шифрования
    @Override public Cipher createBlockMode(CipherMode mode) throws IOException
    {
        // получить допустимые размеры ключей
        int[] keySizes = keyFactory().keySizes(); 
        
        // при неизвестном размере ключей
        if (keySizes == KeySizes.UNRESTRICTED || keySizes.length > 1)
        {
            // в зависимости от режима
            if (mode instanceof CipherMode.ECB) return new BlockMode(this, mode); 
            if (mode instanceof CipherMode.CBC) return new BlockMode(this, mode); 
            if (mode instanceof CipherMode.OFB) return new BlockMode(this, mode); 
            if (mode instanceof CipherMode.CFB) return new BlockMode(this, mode); 

            // режим не поддерживается
            throw new UnsupportedOperationException();
        }
        // получить режим шифрования
        else return createBlockMode(mode, keySizes[0]); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования с неизвестным заранее размером ключа
    ///////////////////////////////////////////////////////////////////////////
    private static class BlockMode extends aladdin.capi.Cipher
    {
        // блочный алгоритм шифрования и режим
        private final BlockCipher blockCipher; private final CipherMode mode; 
        
        // конструктор
        public BlockMode(BlockCipher blockCipher, CipherMode mode)
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
