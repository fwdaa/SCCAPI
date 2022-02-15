package aladdin.capi;
import aladdin.*; 
import aladdin.util.*; 
import java.security.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм выработки имитовставки
///////////////////////////////////////////////////////////////////////////
public abstract class Mac extends RefObject implements IAlgorithm
{
    // тип ключа
    public SecretKeyFactory keyFactory() { return SecretKeyFactory.GENERIC; }
	// размер ключа
	public int[] keySizes() { return keyFactory().keySizes(); } 
    
    // размер MAC-значения
    public abstract int macSize(); 
	// размер блока в байтах
	public abstract int blockSize(); 
    
    // создать интерфейс хэш-алгоритма
    public Hash convertToHash(ISecretKey key) { return new MacHash(this, key); }
    
	// вычислить MAC-значение
	public final byte[] macData(ISecretKey key, byte[] data, int dataOff, int dataLen) 
        throws IOException, InvalidKeyException
	{
		// установить параметры алгоритма
		byte[] mac = new byte[macSize()]; init(key);  

		// захэшировать данные и получить MAC-значение
		update(data, dataOff, dataLen); finish(mac, 0); return mac;
	}
    // инициализировать алгоритм
    public abstract void init(ISecretKey key) throws IOException, InvalidKeyException;
	// захэшировать данные
	public abstract void update(byte[] data, int dataOff, int dataLen) throws IOException;
	// получить MAC-значение
	public abstract int finish(byte[] buf, int bufOff) throws IOException;
    
    ////////////////////////////////////////////////////////////////////////////
    // Интерфейс хэш-алгоритма
    ////////////////////////////////////////////////////////////////////////////
    private class MacHash extends Hash
    {
        // алгоритм вычисления имитовставки и ключ
        private final Mac macAlgorithm; private final ISecretKey key;

        // конструктор
        public MacHash(Mac macAlgorithm, ISecretKey key)
        {
            // сохранить переданные параметры
            this.macAlgorithm = RefObject.addRef(macAlgorithm); 
            this.key          = RefObject.addRef(key         ); 
        }
        // освободить выделенные ресурсы
        @Override protected void onClose() throws IOException
        { 
            // освободить выделенные ресурсы
            RefObject.release(key); 
        
            // освободить выделенные ресурсы
            RefObject.release(macAlgorithm); super.onClose();
        } 
        // размер MAC-значения и размера блока
        @Override public int hashSize () { return macAlgorithm.macSize  (); } 
        @Override public int blockSize() { return macAlgorithm.blockSize(); } 

		// инициализировать алгоритм
		@Override public void init() throws IOException 
        { 
            // инициализировать алгоритм
            try { macAlgorithm.init(key); }
            
            // обработать возможное исключение
            catch (InvalidKeyException e) { throw new IOException(e); }
        }
		// захэшировать данные
		@Override public void update(byte[] data, int dataOff, int dataLen) throws IOException
        {
		    // захэшировать данные
            macAlgorithm.update(data, dataOff, dataLen); 
        }
		// получить MAC-значение
		@Override public int finish(byte[] buf, int bufOff) throws IOException
        {
		    // получить MAC-значение
            return macAlgorithm.finish(buf, bufOff); 
        }
    } 
    ///////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ///////////////////////////////////////////////////////////////////////
    public static void knownTest(Mac macAlgorithm, 
        byte[] key, int iterations, String data, byte[] mac) throws Exception
    {
        // выполнить тест 
        knownTest(macAlgorithm, key, iterations, data.getBytes("UTF-8"), mac); 
    }
    public static void knownTest(Mac macAlgorithm, 
        byte[] key, int iterations, byte[] data, byte[] mac) throws Exception
    {
        // вывести сообщение
        Test.println("Iterations = %1$s", iterations); 
        
        // выделить память для результата
        byte[] result = new byte[macAlgorithm.macSize()]; 
        
        // создать ключ
        try (ISecretKey k = macAlgorithm.keyFactory().create(key))
        {
            // вывести сообщение
            Test.dump("Key", k.value()); Test.dump("Data", data);

            // инициализировать алгоритм 
            macAlgorithm.init(k);  
        }
        // для всех хэшируемых частей
        if (iterations < 256) for (int i = 0; i < iterations; i++)
        {
            // захэшировать данные
            macAlgorithm.update(data, 0, data.length);
        }
        else {
            // выделить буфер требуемого размера
            byte[] buffer = new byte[iterations * data.length]; 

            // для всех хэшируемых частей
            for (int i = 0; i < iterations; i++)
            {
                // скопировать данные
                System.arraycopy(data, 0, buffer, i * data.length, data.length); 
            }
            // захэшировать данные
            macAlgorithm.update(buffer, 0, buffer.length);
        }
        // получить хэш-значение
        macAlgorithm.finish(result, 0); 
        
        // вывести результат
        Test.dump("Required", mac); Test.dump("Result", result);

        // проверить совпадение
        if (!Array.equals(result, 0, mac, 0, mac.length)) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException();
        } 
        // вывести сообщение
        Test.println("OK"); Test.println();
    }
    ///////////////////////////////////////////////////////////////////////////
    // Тест сравнения
    ///////////////////////////////////////////////////////////////////////////
    public static void compatibleTest(IRand rand, Mac macAlgorithm, 
        Mac trustAlgorithm, int[] dataSizes) throws Exception
    {
        // получить допустимые размеры ключей
        int[] keySizes = macAlgorithm.keySizes(); 
        
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
            if (!KeySizes.contains(macAlgorithm.keySizes(), keySize)) continue; 
            
            // сгенерировать ключ
            try (ISecretKey key = macAlgorithm.keyFactory().generate(rand, keySize)) 
            {
                // для всех требуемых размеров
                for (int i = 0; i < dataSizes.length; i++)
                {
                    // сгенерировать случайные данные
                    byte[] data = new byte[dataSizes[i]]; rand.generate(data, 0, data.length);

                    // вывести сообщение
                    Test.dump("Key", key.value()); Test.dump("Data", data, 0, data.length); 

                    // вычислить имитовставку
                    byte[] mac1 = macAlgorithm  .macData(key, data, 0, data.length); 
                    byte[] mac2 = trustAlgorithm.macData(key, data, 0, data.length); 

                    // вывести сообщение
                    Test.dump("MAC1", mac1); Test.dump("MAC2", mac2); 

                    // проверить совпадение имитовставок
                    if (!Arrays.equals(mac1, mac2)) throw new IllegalArgumentException(); 
                    
                    // вывести сообщение
                    Test.println("OK"); Test.println();
               }
            }
        }
    }
}
