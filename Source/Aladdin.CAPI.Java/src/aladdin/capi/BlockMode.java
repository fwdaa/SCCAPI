package aladdin.capi;
import aladdin.*; 
import java.security.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Режим блочного алгоритма шифрования
///////////////////////////////////////////////////////////////////////////////
public abstract class BlockMode extends Cipher
{
	// конструктор
	protected BlockMode(PaddingMode padding)
    
		// сохранить переданные параметры
		{ this.padding = padding; } private PaddingMode padding;
    
    // получить режим дополнения
	protected final PaddingMode padding() { return padding; }
        
    // алгоритм зашифрования данных
	@Override public Transform createEncryption(ISecretKey key, PaddingMode padding) 
        throws IOException, InvalidKeyException
	{
        // указать режим дополнения
        if (this.padding != PaddingMode.ANY) padding = this.padding; 
        
        // сохранить способ дополнения
        PaddingMode oldPadding = this.padding; this.padding = padding; 
        
        // получить режим зашифрования 
        try (Transform encryption = createEncryption(key))
        {
            // указать требуемое дополнение
            return getPadding().createEncryption(encryption, mode()); 
        }
        // восстановить способ дополнения
        finally { this.padding = oldPadding; }
    }
	// алгоритм расшифрования данных
	@Override public Transform createDecryption(ISecretKey key, PaddingMode padding) 
        throws IOException, InvalidKeyException 
	{
        // указать режим дополнения
        if (this.padding != PaddingMode.ANY) padding = this.padding; 
        
        // сохранить способ дополнения
        PaddingMode oldPadding = this.padding; this.padding = padding; 
        
        // получить режим расшифрования 
        try (Transform decryption = createDecryption(key))
        {
            // указать требуемое дополнение
            return getPadding().createDecryption(decryption, mode()); 
        }
        // восстановить способ дополнения
        finally { this.padding = oldPadding; }
    }
    // указать режим дополнения
	protected BlockPadding getPadding() 
	{
        // вернуть отсутствие дополнения
        if (padding == PaddingMode.NONE) return new aladdin.capi.pad.None();
        
        // вернуть дополнение нулями
        if (padding == PaddingMode.ZERO) return new aladdin.capi.pad.Zero();

        // вернуть дополнение PKCS
        if (padding == PaddingMode.PKCS5) return new aladdin.capi.pad.PKCS5(); 

        // вернуть дополнение ISO
        if (padding == PaddingMode.ISO9797) return new aladdin.capi.pad.ISO9797(); 

        // для режима дополнения CTS
        if (padding == PaddingMode.CTS) return new aladdin.capi.pad.CTS(); 

        // при ошибке выбросить исключение
        throw new UnsupportedOperationException();
    }
    ///////////////////////////////////////////////////////////////////////////
    // Изменение режима дополнения (исходный режим должен быть ANY или NONE)
    ///////////////////////////////////////////////////////////////////////////
    public static class PaddingConverter extends BlockMode
    {
        // режим шифрования 
        private final Cipher cipher; 
        
        // конструктор
        public PaddingConverter(Cipher cipher, PaddingMode padding)
        {
            // сохранить переданные параметры
            super(padding); this.cipher = RefObject.addRef(cipher); 
        } 
        // деструктор
        @Override protected void onClose() throws IOException
        { 
            // освободить выделенные ресурсы
            RefObject.release(cipher); super.onClose();
        } 
        // тип ключа
        @Override public SecretKeyFactory keyFactory() { return cipher.keyFactory(); }
        
        // размер блока
        @Override public int blockSize() { return cipher.blockSize(); }
    
        // режим алгоритма
        @Override public CipherMode mode() { return cipher.mode(); } 
    
        // алгоритм зашифрования данных
        @Override protected Transform createEncryption(ISecretKey key) 
            throws IOException, InvalidKeyException
        {
            // алгоритм зашифрования данных
            return cipher.createEncryption(key, PaddingMode.NONE); 
        }
        // алгоритм расшифрования данных
        @Override protected Transform createDecryption(ISecretKey key) 
            throws IOException, InvalidKeyException
        {
            // алгоритм расшифрования данных
            return cipher.createDecryption(key, PaddingMode.NONE); 
        }
    }
};
