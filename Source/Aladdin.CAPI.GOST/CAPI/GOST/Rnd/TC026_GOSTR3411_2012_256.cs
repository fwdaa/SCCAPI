using System;
using System.Runtime.Serialization;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.GOST.Rnd
{
    ///////////////////////////////////////////////////////////////////////////
    // Псевдослучайный генератор случайных данных TK26. 
    ///////////////////////////////////////////////////////////////////////////
    [Serializable]
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public sealed class TC026_GOSTR3411_2012_256 : RefObject, IRand, IDeserializationCallback
    {
        // генератор случайных данных
        [NonSerialized] private TC026 rand; private byte[] seed; 

        // конструктор
        public TC026_GOSTR3411_2012_256(object window, IRand rand)
        {
            // указать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = new Hash.GOSTR3411_2012(256))
            { 
                // выделить память для стартового значения
                seed = new byte[hashAlgorithm.BlockSize - 16]; 

                // сгенерировать стартовое значение
                rand.Generate(seed, 0, seed.Length); 

                // создать генератор случайных данных
                this.rand = new TC026(window, hashAlgorithm, seed, null);
            }
        }
        // конструктор
        public TC026_GOSTR3411_2012_256(object window, byte[] seed, bool test)
        {
            // указать функцию проверки диапазона 
            TC026.CheckQuality check = delegate (byte[] data)
            { 
                // проверить диапазон для псевдослучайной последовательности
                return Rand.CheckRange(data, 101, 156, 101, 155, 5, 25); 
            }; 
            if (!test) check = null; 

            // указать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = new Hash.GOSTR3411_2012(256))
            { 
                // создать генератор случайных данных
                rand = new TC026(window, hashAlgorithm, seed, check); this.seed = seed; 
            }
        }
        // изменить окно для генератора
        public IRand CreateRand(object window) { return Rand.Rebind(this, window); } 

        // инициализировать объект
        public void OnDeserialization(object sender)
        {
            // указать алгоритм хэширования
            using (CAPI.Hash hashAlgorithm = new Hash.GOSTR3411_2012(256))
            { 
                // создать генератор случайных данных
                rand = new TC026(null, hashAlgorithm, seed, null); 
            }
        }
        // стартовое значение
        public byte[] Seed { get { return seed; }}

		// сгенерировать случайные данные
		public void Generate(byte[] data, int dataOff, int dataLen)
        {
		    // сгенерировать случайные данные
            rand.Generate(data, dataOff, dataLen); 
        }
        // описатель окна
        public object Window { get { return rand.Window; }}
    }
}
