using System;
using System.Security.Cryptography;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI
{
	///////////////////////////////////////////////////////////////////////////
	// Генератор случайных данных
	///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
	public sealed class Rand : RefObject, IRand
	{
        // объект и функция генерации данных
        private IDisposable obj; private Action<Byte[]> generator; 
        
        // описатель окна и дополнительный генератор
        private object window; private IRand rand; 

        // изменить окно для генератора
        public static IRand Rebind(IRand rand, object window) 
        {
            // вернуть генератор случайных данных
            return new Rand(rand, window);  
        }
		// конструктор
        private Rand(IRand rand, object window)
        {
            // инициализировать переменные
            this.obj = null; this.generator = null; 

            // сохранить дополнительный генератор
            this.window = window; this.rand = RefObject.AddRef(rand); 
        }
		// конструктор
        public Rand(object window) : this(RNGCryptoServiceProvider.Create(), window) {}
        // конструктор
        public Rand(System.Security.Cryptography.RandomNumberGenerator random, object window) 
        { 
            // сохранить переданные параметры
            this.obj = random as IDisposable; this.generator = random.GetBytes; 

            // сохранить переданные параметры
            this.window = window; this.rand = null; 
        }
        // конструктор
        public Rand(System.Security.Cryptography.RandomNumberGenerator random, IRand rand) 
        { 
            // сохранить переданные параметры
            this.obj = random as IDisposable; this.generator = random.GetBytes; 

            // сохранить генератор случайных данных
            this.rand = RefObject.AddRef(rand); 
            
            // указать используемое окно
            this.window = (rand != null) ? rand.Window : null; 
        }
        // конструктор
        public Rand(System.Random random, object window) 
        { 
            // сохранить переданные параметры
            this.obj = random as IDisposable; this.generator = random.NextBytes; 

            // сохранить переданные параметры
            this.window = window; this.rand = null; 
        }
        // конструктор
        public Rand(System.Random random, IRand rand) 
        { 
            // сохранить переданные параметры
            this.obj = random as IDisposable; this.generator = random.NextBytes; 
            
            // сохранить дополнительный генератор
            this.window = rand.Window; this.rand = RefObject.AddRef(rand); 
        }
        // деструктор
        protected override void OnDispose() 
        { 
            // освободить выделенные ресурсы
            if (obj != null) obj.Dispose(); 
            
            // освободить выделенные ресурсы
            RefObject.Release(rand); base.OnDispose(); 
        }
        // описатель окна
        public object Window { get { return window; }}

        // изменить окно для генератора
        public IRand CreateRand(object window) 
        { 
            // изменить окно для генератора
            return Rand.Rebind(this, window); 
        } 
		// сгенерировать случайные данные
		public void Generate(byte[] data, int dataOff, int dataLen)
		{
			// сгенерировать случайные данные
            byte[] buffer = Generate(dataLen); 

			// скопировать сгенерированные данные
			Array.Copy(buffer, 0, data, dataOff, dataLen); 
		}
		// сгенерировать случайные данные
		public byte[] Generate(int dataLen)
		{
			// выделить буфер для данных
            byte[] buffer = new byte[dataLen]; 
            
			// сгенерировать случайные данные
            if (generator != null) generator(buffer); 

            // выделить дополнительный буфер данных
            if (rand != null) { byte[] buffer2 = new byte[dataLen];

                // сгенерировать дополнительные данные
                rand.Generate(buffer2, 0, dataLen); 

                // выполнить сложение данных
                for (int i = 0; i < dataLen; i++) buffer[i] ^= buffer2[i]; 
            }
            return buffer; 
		}
		///////////////////////////////////////////////////////////////////////
	    // проверить диапазон для псевдослучайных данных
		///////////////////////////////////////////////////////////////////////
	    public static bool CheckRange(
            byte[] data,        // последовательность байтов
		    int ones_min,	    // минимальное число единиц                           (   включительно)
		    int ones_max,	    // максимальное число единиц                          (не включительно)
		    int changes_min,	// минимальное число изменений битов                  (   включительно)
		    int changes_max,	// максимальное число изменений битов                 (не включительно)
		    int max_seq_min,	// минимальная последовательность неизменяемых битов  (   включительно)
		    int max_seq_max	    // максимальная последовательность неизменяемых битов (не включительно)
	    ) { 
            // создать массив для битов 
            byte[] bits = new byte[data.Length * 8]; int ones = 0; 

	        // для всех байтов
	        for (int i = 0, index = 0; i < data.Length; i++)
	        {
		        // для всех битов байта
		        for (int mask = 0x80; mask != 0; index++, mask >>= 1)
		        {
			        // извлечь требуемый бит
			        bits[index] = (byte)(((data[i] & mask) != 0) ? 1 : 0);

			        // увеличить число единиц
			        if (bits[index] != 0) ones++; 
		        }
	        }
	        // проверить число единиц
	        if (ones < ones_min || ones >= ones_max) return false; int changes = 0;

	        // указать начальные условия
	        int max_zeroes_seq = 0; int zeroes_seq = 0;
	        int max_ones_seq   = 0; int ones_seq   = 0;

	        // для всех битов
	        for (int i = 0; i < bits.Length; i++)
	        {
		        // увеличить число изменений 
		        if (i != 0 && bits[i] != bits[i - 1]) 
		        {
			        // проверить на максимальное число
			        if (++changes >= changes_max) return false; 
		        }
		        // при наличии нуля
		        if (bits[i] == 0) 
		        { 
			        // сохранить размер серии единиц
			        if (ones_seq > max_ones_seq) max_ones_seq = ones_seq;  
			
			        // сбросить серию единиц и продолжить серию нулей
			        ones_seq = 0; zeroes_seq++; 

			        // проверить на максимальное число
			        if (zeroes_seq >= max_seq_max) return false; 
		        }
		        else { 
			        // сохранить размер серии нулей
			        if (zeroes_seq > max_zeroes_seq) max_zeroes_seq = zeroes_seq;  

			        // сбросить серию нулей и продолжить серию единиц
			        zeroes_seq = 0; ones_seq++; 

			        // проверить на максимальное число
			        if (ones_seq >= max_seq_max) return false; 
		        }
	        }
	        // учесть размер последней серии
	        if (zeroes_seq > max_zeroes_seq) { max_zeroes_seq = zeroes_seq; }
	        if (ones_seq   > max_ones_seq  ) { max_ones_seq   = ones_seq  ; }

	        // проверить минимальное значение
	        if (changes < changes_min) return false; 
		
	        // проверить минимальные значения
	        return (max_zeroes_seq >= max_seq_min && max_ones_seq >= max_seq_min); 
        }
	}
}
