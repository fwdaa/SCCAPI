package aladdin.capi.ansi.engine;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования DES-X
///////////////////////////////////////////////////////////////////////////
public final class DESX extends Cipher
{
    // алгоритм шифрования блок
    private final Cipher des;
        
	// конструктор
	public DESX(Cipher des) 
    {  
        // сохранить переданные параметры
        this.des = RefObject.addRef(des); 
    } 
    // освободить ресурсы 
    @Override protected void onClose() throws IOException 
    {
        // освободить ресурсы 
        RefObject.release(des); super.onClose();
    }
    // тип ключа
    @Override public final SecretKeyFactory keyFactory() 
    { 
        // тип ключа
        return aladdin.capi.ansi.keys.DESX.INSTANCE; 
    } 
    // размер блока
	@Override public final int blockSize() { return des.blockSize(); }

	// алгоритм зашифрования блока данных
	@Override protected final Transform createEncryption(ISecretKey key) 
        throws IOException, InvalidKeyException
	{
        // проверить тип ключа
        byte[] value = key.value(); if (value == null) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException();
        }
        // проверить размер ключа
        if (value.length != 24) throw new InvalidKeyException(); 

        // вернуть алгоритм зашифрования блока данных
        return new Encryption(des, key); 
	}
	// алгоритм расшифрования блока данных
	@Override protected final Transform createDecryption(ISecretKey key) 
        throws IOException, InvalidKeyException
	{
        // проверить тип ключа
        byte[] value = key.value(); if (value == null) 
        {
            // при ошибке выбросить исключение
            throw new InvalidKeyException();
        }
        // проверить размер ключа
        if (value.length != 24) throw new InvalidKeyException(); 

        // вернуть алгоритм расшифрования блока данных
		return new Decryption(des, key);
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм зашифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Encryption extends BlockTransform
	{
		// используемое преобразование
		private final Transform transform; 
        // дополнительные ключи
        private final byte[] K1; private final byte[] K2;

		// Конструктор
		public Encryption(Cipher des, ISecretKey key) throws IOException, InvalidKeyException
		{ 
			super(8); byte[] value = key.value(); if (value == null) 
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            }
            // извлечь значения ключей
            K1 = Arrays.copyOfRange(value, 8, 16); K2 = Arrays.copyOfRange(value, 16, 24);
            
            // указать ключ
            try (ISecretKey K = des.keyFactory().create(Arrays.copyOfRange(value, 0, 8)))
            {
                // указать используемое преобразование
                transform = des.createEncryption(K, PaddingMode.NONE); 
            }
		}
        // освободить ресурсы 
        @Override protected void onClose() throws IOException 
        {
            // освободить ресурсы 
            RefObject.release(transform); super.onClose();
        }
		///////////////////////////////////////////////////////////////////////
		// Обработка одного блока данных
		///////////////////////////////////////////////////////////////////////
		@Override protected void update(byte[] src, 
            int srcOff, byte[] dest, int destOff) throws IOException
		{
            // скопировать данные
            System.arraycopy(src, srcOff, dest, destOff, 8);
            
            // выполнить сложение с ключом
            for (int i = 0; i < 8; i++) dest[destOff + i] ^= K1[i]; 
            
            // выполнить преобразование
            transform.update(dest, destOff, 8, dest, destOff);

            // выполнить сложение с ключом
            for (int i = 0; i < 8; i++) dest[destOff + i] ^= K2[i]; 
        }
	}
	///////////////////////////////////////////////////////////////////////////
	// Алгоритм расшифрования блока
	///////////////////////////////////////////////////////////////////////////
	public static class Decryption extends BlockTransform
	{
		// используемое преобразование
		private final Transform transform; 
        // дополнительные ключи
        private final byte[] K1; private final byte[] K2;

		// Конструктор
		public Decryption(Cipher des, ISecretKey key) throws IOException, InvalidKeyException
		{ 
			// проверить тип ключа
			super(8); byte[] value = key.value(); if (value == null) 
            {
                // при ошибке выбросить исключение
                throw new InvalidKeyException();
            }
            // извлечь значения ключей
            K1 = Arrays.copyOfRange(value, 8, 16); K2 = Arrays.copyOfRange(value, 16, 24);
            
            // указать ключ
            try (ISecretKey K = des.keyFactory().create(Arrays.copyOfRange(value, 0, 8)))
            {
                // указать используемое преобразование
                transform = des.createDecryption(K, PaddingMode.NONE); 
            }
		}
        // освободить ресурсы 
        @Override protected void onClose() throws IOException 
        {
            // освободить ресурсы 
            RefObject.release(transform); super.onClose();
        }
		///////////////////////////////////////////////////////////////////////
		// Обработка одного блока данных
		///////////////////////////////////////////////////////////////////////
		@Override protected void update(byte[] src, 
            int srcOff, byte[] dest, int destOff) throws IOException
		{
            // скопировать данные
            System.arraycopy(src, srcOff, dest, destOff, 8);
            
            // выполнить сложение с ключом
            for (int i = 0; i < 8; i++) dest[destOff + i] ^= K2[i]; 
            
            // выполнить преобразование
            transform.update(dest, destOff, 8, dest, destOff);

            // выполнить сложение с ключом
            for (int i = 0; i < 8; i++) dest[destOff + i] ^= K1[i]; 
		}
	}
}
