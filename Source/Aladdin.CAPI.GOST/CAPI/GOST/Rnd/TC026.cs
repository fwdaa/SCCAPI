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
        // алгоритм хэширования и текущее состояние
        private CAPI.Hash algorithm; private byte[] U; 
        
        // текущее хэш-значение и номер текущего байта
        private byte[] C; private int offset;

        // конструктор
        public TC026(object window, CAPI.Hash algorithm, byte[] seed)
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
            this.window = window; this.algorithm = RefObject.AddRef(algorithm); 

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
                // выполнить инкремент состояния
                for (int i = U.Length - 1; i >= 0; i--) { if (++U[i] != 0) break; }

                // вычислить хэш-значение
                algorithm.Init(); algorithm.Update(U, 0, U.Length); 

                // сохранить хэш-значение
                algorithm.Finish(data, dataOff + dataLen - C.Length); 
            }
            // для неполного блока
            if (dataLen > 0)
            {
                // выполнить инкремент состояния
                for (int i = U.Length - 1; i >= 0; i--) { if (++U[i] != 0) break; }

                // вычислить хэш-значение
                algorithm.Init(); algorithm.Update(U, 0, U.Length); 

                // сохранить хэш-значение
                algorithm.Finish(C, 0); offset = C.Length - dataLen; 

                // скопировать случайные данные
                Array.Copy(C, offset, data, dataOff, dataLen); 
            }
        }
        // описатель окна
        public object Window { get { return window; }} private object window; 
    }
}
