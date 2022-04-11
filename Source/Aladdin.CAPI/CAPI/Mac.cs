using System;
using System.Text;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
	// Алгоритм выработки имитовставки
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public abstract class Mac : RefObject, IAlgorithm
	{
        // тип ключа
        public virtual SecretKeyFactory KeyFactory  { get { return SecretKeyFactory.Generic; }}

		// размер MAC-значения и размер блока
        public abstract int MacSize   { get; } 
        public abstract int BlockSize { get; } 

        // создать интерфейс хэш-алгоритма
        public Hash ConvertToHash(ISecretKey key) { return new MacHash(this, key); }

		// вычислить MAC-значение
		public byte[] MacData(ISecretKey key, byte[] data, int dataOff, int dataLen)
		{
			// установить параметры алгоритма
			byte[] hash = new byte[MacSize]; Init(key);  

			// захэшировать данные и получить MAC-значение
			Update(data, dataOff, dataLen); Finish(hash, 0); return hash;
		}
		// инициализировать алгоритм
		public abstract void Init(ISecretKey key);

		// захэшировать данные
		public abstract void Update(byte[] data, int dataOff, int dataLen);

		// получить MAC-значение
		public abstract int Finish(byte[] buf, int bufOff);

        ////////////////////////////////////////////////////////////////////////////
        // Интерфейс хэш-алгоритма
        ////////////////////////////////////////////////////////////////////////////
        private class MacHash : Hash
        {
            // алгоритм вычисления имитовставки и ключ
            private Mac macAlgorithm; private ISecretKey key;

            // конструктор
            public MacHash(Mac macAlgorithm, ISecretKey key)
            {
                // сохранить переданные параметры
                this.macAlgorithm = RefObject.AddRef(macAlgorithm); 
                this.key          = RefObject.AddRef(key         ); 
            }
            // освободить выделенные ресурсы
            protected override void OnDispose() 
            { 
                // освободить выделенные ресурсы
                RefObject.Release(key); 
        
                // освободить выделенные ресурсы
                RefObject.Release(macAlgorithm); base.OnDispose();
            } 
		    // размер MAC-значения и размера блока
            public override int HashSize  { get { return macAlgorithm.MacSize;   }} 
            public override int BlockSize { get { return macAlgorithm.BlockSize; }} 

		    // инициализировать алгоритм
		    public override void Init() { macAlgorithm.Init(key); }

		    // захэшировать данные
		    public override void Update(byte[] data, int dataOff, int dataLen)
            {
		        // захэшировать данные
                macAlgorithm.Update(data, dataOff, dataLen); 
            }
		    // получить MAC-значение
		    public override int Finish(byte[] buf, int bufOff)
            {
		        // получить MAC-значение
                return macAlgorithm.Finish(buf, bufOff); 
            }
        } 
        ////////////////////////////////////////////////////////////////////////////
        // Тест известного ответа
        ////////////////////////////////////////////////////////////////////////////
        public static void KnownTest(Mac macAlgorithm, byte[] key, int iterations, string data, byte[] hash) 
        {
            // выполнить тест 
            KnownTest(macAlgorithm, key, iterations, Encoding.UTF8.GetBytes(data), hash); 
        }
        public static void KnownTest(Mac macAlgorithm, byte[] key, int iterations, byte[] data, byte[] mac) 
        {
            // вывести сообщение
            Test.WriteLine("Iterations = {0}", iterations); 

            // выделить память для результата
            byte[] result = new byte[macAlgorithm.MacSize]; 

            // создать ключ
            using (ISecretKey k = macAlgorithm.KeyFactory.Create(key))
            { 
                // вывести сообщение
                Test.Dump("Key", k.Value); Test.Dump("Data", data); 
            
                // инициализировать алгоритм
                macAlgorithm.Init(k); 
            }
            // для всех хэшируемых частей
            if (iterations < 256) for (int i = 0; i < iterations; i++)
            {
                // захэшировать данные
                macAlgorithm.Update(data, 0, data.Length);
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
                macAlgorithm.Update(buffer, 0, buffer.Length);
            }
            // получить хэш-значение
            macAlgorithm.Finish(result, 0); 
        
            // вывести сообщение
            Test.Dump("Required", mac); Test.Dump("MAC", result); 

            // проверить совпадение
            if (!Arrays.Equals(result, 0, mac, 0, mac.Length)) 
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
            Mac macAlgorithm, Mac trustAlgorithm, int[] dataSizes) 
        {
            // получить допустимые размеры ключей
            int[] keySizes = macAlgorithm.KeyFactory.KeySizes; 
        
            // при отсутствии ограничений на размер ключа
            if (keySizes == CAPI.KeySizes.Unrestricted || keySizes.Length > 32)
            {
                // скорректировать допустимые размеры ключей
                keySizes = new int[] { 0, 8, 16, 24, 32, 64 }; 
            }
            // для всех размеров ключей
            foreach (int keySize in keySizes)
            { 
                // сгенерировать ключ
                using (ISecretKey key = macAlgorithm.KeyFactory.Generate(rand, keySize)) 
                {
                    // для всех требуемых размеров
                    for (int i = 0; i < dataSizes.Length; i++)
                    {
                        // сгенерировать случайные данные
                        byte[] data = new byte[dataSizes[i]]; rand.Generate(data, 0, data.Length);
            
                        // вывести сообщение
                        Test.Dump("Key", key.Value); Test.Dump("Data", data, 0, data.Length); 

                        // вычислить имитовставку
                        byte[] mac1 = macAlgorithm  .MacData(key, data, 0, data.Length); 
                        byte[] mac2 = trustAlgorithm.MacData(key, data, 0, data.Length); 

                        // вывести сообщение
                        Test.Dump("MAC1", mac1); Test.Dump("MAC2", mac2); 

                        // проверить совпадение имитовставок
                        if (!Arrays.Equals(mac1, mac2)) throw new ArgumentException(); 

                        // вывести сообщение
                        Test.WriteLine("OK"); Test.WriteLine();
                    }
                }
            }
        }
	}
}
