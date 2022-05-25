using System;
using System.Diagnostics.CodeAnalysis; 

namespace Aladdin.CAPI.Rnd
{
    ///////////////////////////////////////////////////////////////////////////
    // Генератор нулевых данных
    ///////////////////////////////////////////////////////////////////////////
    [SuppressMessage("Microsoft.Design", "CA1063:ImplementIDisposableCorrectly")]
    public sealed class Zero : RefObject, IRand
    {
        // конструктор
        public Zero(object window) 
            
            // сохранить переданные параметры
            { this.window = window; } private object window; 

        // изменить окно для генератора
        public IRand CreateRand(object window) 
        { 
            // изменить окно для генератора
            return Rand.Rebind(this, window); 
        } 
        // описатель окна
        public object Window { get { return window; }} 

        // сгенерировать случайные данные
        public void Generate(byte[] data, int dataOff, int dataLen)
        {
            // указать нулевые данные
            for (int i = 0; i < dataLen; i++) data[dataOff + i] = 0; 
        }
    }
}
