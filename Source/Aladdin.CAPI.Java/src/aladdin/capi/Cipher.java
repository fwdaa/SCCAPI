package aladdin.capi;
import aladdin.*; 
import java.security.*;
import java.io.*;
import java.util.*;

///////////////////////////////////////////////////////////////////////////
// Симметричный алгоритм шифрования
///////////////////////////////////////////////////////////////////////////
public class Cipher extends RefObject implements IAlgorithm
{
    // тип ключа
    public SecretKeyFactory keyFactory() { return SecretKeyFactory.GENERIC; }
    // размер ключа
    public int[] keySizes () { return keyFactory().keySizes(); }
    
    // размер блока
	public int blockSize() { return 1; }
    
    // режим алгоритма
    public CipherMode mode() { return null; } 
    
	// зашифровать данные
	public final int encrypt(ISecretKey key, PaddingMode padding, 
        byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff) 
        throws IOException, InvalidKeyException
	{
        // установить ключ алгоритма
        try (Transform encryption = createEncryption(key, padding))
        {
            // зашифровать данные
            return encryption.transformData(data, dataOff, dataLen, buf, bufOff); 
        }
	}
	// зашифровать данные
	public final byte[] encrypt(ISecretKey key, 
        PaddingMode padding, byte[] data, int dataOff, int dataLen) 
        throws IOException, InvalidKeyException
	{
        // установить ключ алгоритма
        try (Transform encryption = createEncryption(key, padding))
        {
            // зашифровать данные
            return encryption.transformData(data, dataOff, dataLen); 
        }
	}
	// расшифровать данные
	public final int decrypt(ISecretKey key, PaddingMode padding, 
        byte[] data, int dataOff, int dataLen, byte[] buf, int bufOff) 
        throws IOException, InvalidKeyException
	{
		// установить ключ алгоритма
		try (Transform decryption = createDecryption(key, padding))
        {
            // расшифровать данные
            return decryption.transformData(data, dataOff, dataLen, buf, bufOff); 
        }
    }
	// расшифровать данные
	public final byte[] decrypt(ISecretKey key, 
        PaddingMode padding, byte[] data, int dataOff, int dataLen) 
        throws IOException, InvalidKeyException
	{
		// установить ключ алгоритма
		try (Transform decryption = createDecryption(key, padding))
        {
            // расшифровать данные
            return decryption.transformData(data, dataOff, dataLen); 
        }
    }
    // алгоритм зашифрования данных
	public Transform createEncryption(ISecretKey key, PaddingMode padding) 
        throws IOException, InvalidKeyException
	{
		// получить режим зашифрования 
		return createEncryption(key); 
	}
	// алгоритм расшифрования данных
	public Transform createDecryption(ISecretKey key, PaddingMode padding) 
        throws IOException, InvalidKeyException 
	{
		// получить режим расшифрования 
        return createDecryption(key); 
	}
    // тождественное преобразование
    protected Transform createEncryption(ISecretKey key) 
        throws IOException, InvalidKeyException { return new Transform(); }
    
    // тождественное преобразование
    protected Transform createDecryption(ISecretKey key) 
        throws IOException, InvalidKeyException { return new Transform(); }
    
    // создать алгоритм шифрования ключа
    public aladdin.capi.KeyWrap createKeyWrap(PaddingMode padding)
    {
        // создать алгоритм зашифрования ключа
        return new KeyWrap(this, padding); 
    }
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм шифрования ключа на основе алгоритма шифрования
    ///////////////////////////////////////////////////////////////////////////
    private static class KeyWrap extends aladdin.capi.KeyWrap
    {
        // используемый алгоритм шифрования и способ дополнения 
        private final Cipher cipher; private final PaddingMode padding; 

        // конструктор
        public KeyWrap(Cipher cipher, PaddingMode padding) 
        {	
            // сохранить переданные параметры
            this.cipher = RefObject.addRef(cipher); this.padding = padding;  
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException
        { 
            // освободить выделенные ресурсы
            RefObject.release(cipher); super.onClose(); 
        }
        // тип ключа
        @Override public SecretKeyFactory keyFactory() { return cipher.keyFactory(); } 
        // размер ключей
        @Override public int[] keySizes() { return cipher.keySizes(); } 
        
        // зашифровать ключ
        @Override public byte[] wrap(IRand rand, ISecretKey key, ISecretKey CEK) 
            throws IOException, InvalidKeyException
        {
            // проверить тип ключа
            if (CEK.value() == null) throw new InvalidKeyException();

            // зашифровать ключ
            return cipher.encrypt(key, padding, CEK.value(), 0, CEK.value().length); 
        }
        // расшифровать ключ
        @Override public ISecretKey unwrap(ISecretKey key, byte[] wrappedCEK, 
            SecretKeyFactory keyFactory) throws IOException, InvalidKeyException
        {
            // расшифровать ключ
            return keyFactory.create(cipher.decrypt(
                key, padding, wrappedCEK, 0, wrappedCEK.length
            )); 
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест известного ответа и обратимости
    ///////////////////////////////////////////////////////////////////////////
    public static void knownTest(Cipher cipher, PaddingMode padding, 
        byte[] key, byte[] plaintext, byte[] ciphertext) throws Exception
    {
        // вывести параметры алгоритмов
        if (cipher.mode() != null) cipher.mode().dump();
        
        // указать используемый ключ
        try (ISecretKey k = cipher.keyFactory().create(key))
        {
            // вывести сообщение
            Test.dump("Key", k.value()); Test.dump("Data", plaintext);
            
            // зашифровать данные
            byte[] result = cipher.encrypt(k, padding, plaintext, 0, plaintext.length); 
            
            // вывести сообщение
            Test.dump("Required", ciphertext); Test.dump("Encrypted", result); 

            // проверить совпадение результата
            if (ciphertext != null && !Arrays.equals(result, ciphertext)) 
            {
                // при ошибке выбросить исключение
                throw new IllegalArgumentException();
            } 
            // расшифровать данные
            result = cipher.decrypt(k, padding, result, 0, result.length);
            
            // вывести сообщение
            Test.dump("Decrypted", result); 
        
            // проверить совпадение результата
            if (!Arrays.equals(result, plaintext)) throw new IllegalArgumentException(); 
        
            // вывести сообщение
            Test.println("OK"); Test.println();
        }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест сравнения
    ///////////////////////////////////////////////////////////////////////////
    public static void compatibleTest(IRand rand, 
        Cipher cipherAlgorithm, Cipher trustAlgorithm, 
        PaddingMode padding, int[] dataSizes) throws Exception
    {
        // получить допустимые размеры ключей
        int[] keySizes = cipherAlgorithm.keySizes(); 
        
        // при отсутствии ограничений на размер ключа
        if (keySizes == KeySizes.UNRESTRICTED || keySizes.length > 32)
        {
            // скорректировать допустимые размеры ключей
            keySizes = new int[] { 0, 8, 16, 24, 32, 64 }; 
        }
        // для всех размеров ключей
        for (int keySize : keySizes)
        { 
            // проверить поддержку размера ключа
            if (!KeySizes.contains(cipherAlgorithm.keySizes(), keySize)) continue; 
            
            // сгенерировать ключ 
            try (ISecretKey key = cipherAlgorithm.keyFactory().generate(rand, keySize)) 
            {
                // для всех требуемых размеров
                for (int i = 0; i < dataSizes.length; i++)
                {
                    // сгенерировать случайные данные
                    byte[] data = new byte[dataSizes[i]]; rand.generate(data, 0, data.length);

                    // вывести параметры алгоритмов
                    if (cipherAlgorithm.mode() != null) cipherAlgorithm.mode().dump();

                    // вывести сообщение
                    Test.dump("Key", key.value()); Test.dump("Data", data, 0, data.length); 

                    // зашифровать данные
                    byte[] encrypted1 = cipherAlgorithm.encrypt(key, padding, data, 0, data.length); 
                    byte[] encrypted2 = trustAlgorithm .encrypt(key, padding, data, 0, data.length); 
                    
                    // вывести сообщение
                    Test.dump("Encrypted1", encrypted1); Test.dump("Encrypted2", encrypted2); 

                    // проверить совпадение шифртекста
                    if (!Arrays.equals(encrypted1, encrypted2)) throw new IllegalArgumentException(); 

                    // расшифровать данные
                    byte[] decrypted = cipherAlgorithm.decrypt(
                        key, padding, encrypted1, 0, encrypted1.length
                    ); 
                    // сравнить результаты
                    if (!Arrays.equals(decrypted, data)) throw new IllegalArgumentException(); 

                    // вывести сообщение
                    Test.println("OK"); Test.println();
                }
            }
        }
    }
}
