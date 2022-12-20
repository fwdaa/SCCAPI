using System;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.GOST.Rnd
{
    ///////////////////////////////////////////////////////////////////////////
    // Псевдослучайный генератор случайных данных TK26. 
    // Генерация производится в сторону байтов с младшими адресами. 
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public class TC026 : RefObject, IRand
    {
        // функция проверки качества 
        public delegate bool CheckQuality(byte[] data); 

        // алгоритм хэширования и текущее состояние
        private CAPI.Hash algorithm; private byte[] U; 
        
        // текущее хэш-значение и номер текущего байта
        private byte[] C; private int offset; private CheckQuality check; 

        // конструктор
        public TC026(object window, CAPI.Hash algorithm, byte[] seed, CheckQuality check)
        {
            // определить размер блока функции хэширования
            int blockSize = algorithm.BlockSize; if (blockSize < 64) 
            {
                // при ошибке выбросить исключение
                throw new ArgumentException();
            }
            // проверить корректность параметров
            if (seed.Length < 32 || seed.Length > blockSize - 16) 
            {
                // при ошибке выбросить исключение
                throw new ArgumentException();
            }
            // сохранить переданные параметры
            this.window = window; this.check = check; 
            
            // сохранить алгоритм хэширования 
            this.algorithm = RefObject.AddRef(algorithm); 

            // выделить буферы требуемого размера
            U = new byte[blockSize - 1]; C = new byte[algorithm.HashSize]; 
            
            // скопировать начальное значение
            Array.Copy(seed, 0, U, 0, seed.Length); offset = 0; 

            // выполнить дополнение нулями
            for (int i = seed.Length; i < U.Length; i++) U[i] = 0; 
        }
        // освободить ресурсы
        protected override void OnDispose() 
        { 
            // освободить ресурсы
            RefObject.Release(algorithm); base.OnDispose();
        }
        // изменить окно для генератора
        public IRand CreateRand(object window) { return Rand.Rebind(this, window); } 

		// сгенерировать случайные данные
		public void Generate(byte[] data, int dataOff, int dataLen)
        {
            // проверить необходимость действий
            if (dataLen == 0) return; if (offset > 0)
            {
                // определить число копируемых байтов
                int length = (offset > dataLen) ? dataLen : offset; 

                // скопировать случайные данные
                Array.Copy(C, offset - length, data, dataOff + dataLen - length, length); 

                // вычислить размер оставшихся данных
                offset -= length; dataLen -= length; 
            }
            // для всех целых блоков
            for (; dataLen >= C.Length; dataLen -= C.Length)
            {
                // сгенерировать новый блок
                GenerateNext(); 

                // скопировать хэш-значение в выходные данные
                Array.Copy(C, 0, data, dataOff + dataLen - C.Length, C.Length); 
            }
            // для неполного блока
            if (dataLen > 0)
            {
                // сгенерировать новый блок
                GenerateNext(); offset = C.Length - dataLen; 

                // скопировать случайные данные
                Array.Copy(C, offset, data, dataOff, dataLen); 
            }
        }
        private void GenerateNext()
        {
            do {
                // выполнить инкремент состояния
                for (int i = U.Length - 1; i >= 0; i--) { if (++U[i] != 0) break; }

                // захэшировать состояние
                algorithm.Init(); algorithm.Update(U, 0, U.Length); 

                // вычислить хэш-значение
                algorithm.Finish(C, 0); 
            }
            // проверить качество последовательности
            while (check != null && !check(C)); 
        }
        // описатель окна
        public object Window { get { return window; }} private object window; 

	    // проверить диапазон 
	    private static bool CheckRanges(
            byte[] data,        // 32-байтовая последовательность
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

