package aladdin.capi;
import aladdin.*; 
import aladdin.util.*; 
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////
public abstract class Hash extends RefObject implements IAlgorithm
{
	// размер хэш-значения и размер блока в байтах
	public abstract int hashSize (); 
    public abstract int blockSize(); 
    
    // вычислить хэш-значение
	public final byte[] hashData(byte[] data, int dataOff, int dataLen) throws IOException
	{
		// установить параметры алгоритма
		byte[] hash = new byte[hashSize()]; init();  

		// захэшировать данные и получить хэш-значение
		update(data, dataOff, dataLen); finish(hash, 0); return hash;
	}
    // инициализировать алгоритм
    public abstract void init() throws IOException;
	// захэшировать данные
	public abstract void update(byte[] data, int dataOff, int dataLen) throws IOException;
	// получить хэш-значение
	public abstract int finish(byte[] buf, int bufOff) throws IOException;
    
    ///////////////////////////////////////////////////////////////////////
    // Тест известного ответа
    ///////////////////////////////////////////////////////////////////////
    public static void knownTest(Hash hashAlgorithm, 
        int count, String data, byte[] hash) throws Exception
    {
        // выполнить тест 
        knownTest(hashAlgorithm, count, data.getBytes("UTF-8"), hash); 
    }
    public static void knownTest(Hash hashAlgorithm, 
        int iterations, byte[] data, byte[] hash) throws Exception
    {
        // вывести сообщение
        Test.println("Iterations = %1$s", iterations); 
        
        // вывести сообщение
        Test.dump("Data"    , data); 
        Test.dump("Required", hash); 

        // выделить память для результата
        byte[] result = new byte[hashAlgorithm.hashSize()]; 

        // инициализировать алгоритм 
        hashAlgorithm.init();  

        // для всех хэшируемых частей
        if (iterations < 256) for (int i = 0; i < iterations; i++)
        {
            // захэшировать данные
            hashAlgorithm.update(data, 0, data.length);
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
            hashAlgorithm.update(buffer, 0, buffer.length);
        }
        // получить хэш-значение
        hashAlgorithm.finish(result, 0); 

        // вывести сообщение
        Test.dump("Result", result); 

        // проверить совпадение
        if (!Array.equals(result, 0, hash, 0, hash.length)) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException(); 
        }
        // вывести сообщение
        Test.println("OK"); Test.println(); 
    }
    ///////////////////////////////////////////////////////////////////////
    // Тест сравнения
    ///////////////////////////////////////////////////////////////////////
    public static void compatibleTest(IRand rand, 
        Hash hashAlgorithm, Hash trustAlgorithm, int[] dataSizes) throws Exception
    {
        // для всех допустимых размеров
        for (int i = 0; i < dataSizes.length; i++)
        {
            // сгенерировать случайные данные
            byte[] data = new byte[dataSizes[i]]; rand.generate(data, 0, data.length);

            // вывести сообщение
            Test.dump("Data", data, 0, data.length); 

            // вычислить хэш-значения
            byte[] hash1 = hashAlgorithm .hashData(data, 0, data.length); 
            byte[] hash2 = trustAlgorithm.hashData(data, 0, data.length); 

            // вывести сообщение
            Test.dump("Hash1", hash1); Test.dump("Hash2", hash2); 

            // проверить совпадение хэш-значений
            if (!Arrays.equals(hash1, hash2)) throw new IllegalArgumentException(); 

            // вывести сообщение
            Test.println("OK"); Test.println();
        }
    }
}
