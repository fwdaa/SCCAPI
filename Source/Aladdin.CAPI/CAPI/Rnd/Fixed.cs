using System;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.Rnd
{
    ///////////////////////////////////////////////////////////////////////////
    // Генератор фиксированных данных
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public sealed class Fixed : RefObject, IRand
    {
        // список значений и номер теукущего значения
        private byte[][] values; private int index;  

        // конструктор
        public Fixed(params byte[][] values)
        { 
            // сохранить переданные параметры
            this.values = values; index = 0; 
        }
        // изменить окно для генератора
        public IRand CreateRand(object window) 
        { 
            // вернуть генератор случайных данных
            return RefObject.AddRef(this); 
        } 
        public void Generate(byte[] data, int dataOff, int dataLen) 
        {
	        // сгенерировать случайные данные
	        byte[] buffer = Generate(dataLen); 

            // скопировать данные
            Array.Copy(buffer, 0, data, dataOff, dataLen); 
        }
        public byte[] Generate(int dataLen) 
        {
            // проверить совпадение размеров
            if (index >= values.Length || values[index].Length != dataLen) 
            {
                // при ошибке выбросить исключение
                throw new ArgumentException(); 
            }
            // указать случайные данные
            return values[index++]; 
        }
        // описатель окна
        public object Window { get { return null; }}

        public void Dump()
        {
            // для всех случайных данных
            for (int i = 0; i < values.Length; i++)
            {
                // указать номер случайных данных
                String name = String.Format("Random{0}", i); 
        
                // вывести случайные данные
                Test.Dump(name, values[i]);
            }
        }
    }
}
