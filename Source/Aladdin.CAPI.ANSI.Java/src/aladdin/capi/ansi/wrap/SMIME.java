package aladdin.capi.ansi.wrap;
import aladdin.*; 
import aladdin.capi.*; 
import java.security.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Шифрование ключа S/MIME
///////////////////////////////////////////////////////////////////////////
public class SMIME extends KeyWrap
{
    // блочный алгоритм шифрования и его CBC-режим
	private final IBlockCipher blockCipher; private final Cipher modeCBC; 

	// конструктор 
	public SMIME(IBlockCipher blockCipher, byte[] iv) throws IOException
    {
        // указать режим алгоритма
        CipherMode cipherMode = new CipherMode.CBC(iv); 
        
        // создать режим шифрования
        modeCBC = blockCipher.createBlockMode(cipherMode); 
        
        // сохранить переданные параметры
        this.blockCipher = RefObject.addRef(blockCipher); 
    }
    // освободить выделенные ресурсы
    @Override protected void onClose() throws IOException  
    { 
        // освободить выделенные ресурсы
        RefObject.release(modeCBC); RefObject.release(blockCipher); super.onClose();
    }
    // тип ключа
	@Override public final SecretKeyFactory keyFactory() { return modeCBC.keyFactory(); } 
    // размер ключей
	@Override public final int[] keySizes() { return modeCBC.keySizes(); }
    
	// зашифровать ключ
	@Override public byte[] wrap(IRand rand, ISecretKey key, ISecretKey wrappedKey) 
        throws IOException, InvalidKeyException
	{
		// проверить тип ключа
		byte[] CEK = wrappedKey.value(); if (CEK == null)
		{
			// при ошибке выбросить исключение
			throw new InvalidKeyException();
		}
		// определить размер блока алгоритма шифрования
		int blockSize = modeCBC.blockSize(); if (CEK.length < 3) 
		{
			// при ошибке выбросить исключение
			throw new InvalidKeyException();
		}
		// определить размер зашифровываемых данных
		int length = (4 + CEK.length + blockSize - 1) / blockSize * blockSize; 

		// проверить наличие по крайней мере двух блоков
		byte[] wrappedCEK = new byte[(length == blockSize) ? length + blockSize : length];  

		// записать контрольные данные
		wrappedCEK[0] = (byte) CEK.length;	wrappedCEK[1] = (byte)~CEK[0]; 
		wrappedCEK[2] = (byte)~CEK[1];		wrappedCEK[3] = (byte)~CEK[2];
 
		// скопировать ключ шифрования данных
		System.arraycopy(CEK, 0, wrappedCEK, 4, CEK.length); 

		// сгенерировать случайное дополнение
		rand.generate(wrappedCEK, 4 + CEK.length, wrappedCEK.length - 4 - CEK.length); 

		// создать режим зашифрования CBC
		try (Transform encryption = modeCBC.createEncryption(key, PaddingMode.NONE))
        { 
            // зашифровать сформированные данные
            encryption.init(); encryption.update(wrappedCEK, 0, wrappedCEK.length, wrappedCEK, 0); 
			
            // повторно зашифровать сформированные данные
            encryption.finish(wrappedCEK, 0, wrappedCEK.length, wrappedCEK, 0); return wrappedCEK; 
        }
	}
	// расшифровать ключ
	@Override public ISecretKey unwrap(ISecretKey key, 
        byte[] wrappedCEK, SecretKeyFactory keyFactory) 
            throws IOException, InvalidKeyException
	{
		// определить размер блока
		int blockSize = modeCBC.blockSize(); byte[] start = new byte[blockSize];  
        
		// проверить размер зашифрованных данных
		if ((wrappedCEK.length % blockSize) != 0) throw new IOException();
            
		// проверить размер зашифрованных данных
        if (wrappedCEK.length < blockSize * 2) throw new IOException();
        
        // получить алгоритм шифрования блока
        wrappedCEK = wrappedCEK.clone();
        
		// извлечь предпоследний блок
		System.arraycopy(wrappedCEK, wrappedCEK.length - 2 * blockSize, start, 0, blockSize); 
        
        // создать режим CBC
		try (Cipher mode = blockCipher.createBlockMode(new CipherMode.CBC(start)))
        {
            // расшифровать данные последнего блока
            mode.decrypt(key, PaddingMode.NONE, wrappedCEK, wrappedCEK.length - blockSize, 
                blockSize, wrappedCEK, wrappedCEK.length - blockSize
            );
        }
		// использовать последний блок в качестве синхропосылки
		System.arraycopy(wrappedCEK, wrappedCEK.length - blockSize, start, 0, blockSize); 

        // создать режим CBC
		try (Cipher mode = blockCipher.createBlockMode(new CipherMode.CBC(start)))
        {
            // расшифровать данные, кроме последнего блока
            mode.decrypt(key, PaddingMode.NONE, wrappedCEK, 
                0, wrappedCEK.length - blockSize, wrappedCEK, 0
            );
        }
		// создать режим расшифрования CBC
		try (Transform decryption = modeCBC.createDecryption(key, PaddingMode.NONE))
        {
            // расшифровать данные при втором проходе
            decryption.transformData(wrappedCEK, 0, wrappedCEK.length, wrappedCEK, 0); 
        }
		// проверить размер ключа шифрования данных
		if (wrappedCEK[0] < 3 || wrappedCEK[0] > wrappedCEK.length - 4) 
		{
			// при ошибке выбросить исключение
			throw new IOException();
		}
		// проверить контрольные данные
		if (wrappedCEK[1] != (byte)~wrappedCEK[4]) throw new IOException();
		if (wrappedCEK[2] != (byte)~wrappedCEK[5]) throw new IOException();
		if (wrappedCEK[3] != (byte)~wrappedCEK[6]) throw new IOException();

		// выделить память для расшифрованного ключа
		byte[] CEK = new byte [wrappedCEK[0]]; 
			
		// извлечь значение ключа
		System.arraycopy(wrappedCEK, 4, CEK, 0, CEK.length); 
        
		// вернуть расшифрованный ключ
        return keyFactory.create(CEK);  
	}
}
