using System; 
using System.Text;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Алгоритм хэширования
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class Hash : RefObject, IAlgorithm
	{
		// размер хэш-значения и блока в байтах
		public abstract int HashSize  { get; } 
        public abstract int BlockSize { get; } 
        
		// получить хэш-значение
		public byte[] HashData(byte[] data, int dataOff, int dataLen)
		{
			// установить параметры алгоритма
			byte[] hash = new byte[HashSize]; Init();  

			// захэшировать данные и получить хэш-значение
			Update(data, dataOff, dataLen); Finish(hash, 0); return hash;
		}
        // инициализировать алгоритм
        public abstract void Init();

		// захэшировать данные
		public abstract void Update(byte[] data, int dataOff, int dataLen);

		// получить хэш-значение
		public abstract int Finish(byte[] buf, int bufOff);
#if !STANDALONE
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void KnownTest(Hash hashAlgorithm, int iterations, string data, byte[] hash) 
        {
            // выполнить тест 
            KnownTest(hashAlgorithm, iterations, Encoding.UTF8.GetBytes(data), hash); 
        }
        public static void KnownTest(Hash hashAlgorithm, int iterations, byte[] data, byte[] hash)
        {
            // вывести сообщение
            Test.WriteLine("Iterations = {0}", iterations); 

            // вывести сообщение
            Test.Dump("Data", data); Test.Dump("Required", hash); 

            // выделить память для результата
            byte[] result = new byte[hashAlgorithm.HashSize]; 
        
            // инициализировать алгоритм 
            hashAlgorithm.Init();  

            // для всех хэшируемых частей
            if (iterations < 256) for (int i = 0; i < iterations; i++)
            {
                // захэшировать данные
                hashAlgorithm.Update(data, 0, data.Length);
            }
            else {
                // выделить буфер требуемого размера
                byte[] buffer = new byte[iterations * data.Length]; 

                // для всех хэшируемых частей
                for (int i = 0; i < iterations; i++)
                {
                    // скопировать данные
                    Array.Copy(data, 0, buffer, i * data.Length, data.Length); 
                }
                // захэшировать данные
                hashAlgorithm.Update(buffer, 0, buffer.Length);
            }
            // получить хэш-значение
            hashAlgorithm.Finish(result, 0); 
        
            // вывести сообщение
            Test.Dump("Hash", result); 

            // проверить совпадение
            if (!Arrays.Equals(result, hash))
            {
                // при ошибке выбросить исключение
                throw new ArgumentException(); 
            }
            // вывести сообщение
            Test.WriteLine("OK"); Test.WriteLine();
        }
        ////////////////////////////////////////////////////////////////////////////
        // Тест сравнения
        ////////////////////////////////////////////////////////////////////////////
        public static void CompatibleTest(IRand rand, 
            Hash hashAlgorithm, Hash trustAlgorithm, int[] dataSizes) 
        {
            // для всех размеров данных
            for (int i = 0; i < dataSizes.Length; i++)
            {
                // сгенерировать случайные данные
                byte[] data = new byte[dataSizes[i]]; rand.Generate(data, 0, data.Length);
            
                // вывести сообщение
                Test.Dump("Data", data, 0, data.Length); 

                // вычислить хэш-значения
                byte[] hash1 = hashAlgorithm .HashData(data, 0, data.Length); 
                byte[] hash2 = trustAlgorithm.HashData(data, 0, data.Length); 
        
                // вывести сообщение
                Test.Dump("Hash1", hash1); Test.Dump("Hash2", hash2); 

                // проверить совпадение хэш-значений
                if (!Arrays.Equals(hash1, hash2)) throw new ArgumentException(); 

                // вывести сообщение
                Test.WriteLine("OK"); Test.WriteLine();
            }
        }
#endif 
	}
}
