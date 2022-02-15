using System;

namespace Aladdin.Math
{
    ////////////////////////////////////////////////////////////////////////////
    // Создание вектора
    ////////////////////////////////////////////////////////////////////////////
    public sealed class VectorBuilder
    {
        // коэффициенты вектора
        private UInt32[] magnitude; private int m; 

        // конструктор
        public VectorBuilder(int m) 
        {
            // создать список коэффициентов вектора
            magnitude = new UInt32[(m + 31) / 32]; this.m = m;  
        }
        // получить значение бита
        public int this[int index] 
        { 
            get {
                // определить позицию бита
                int word = (m - 1 - index) / 32; int bit = (m - 1 - index) % 32; 
    
                // вернуть значение бита
                return ((magnitude[magnitude.Length - 1 - word] & (1 << bit)) != 0) ? 1 : 0; 
            }
            set {
                // определить позицию бита
                int word = (m - 1 - index) / 32; int bit = (m - 1 - index) % 32; 

                // установить значение бита
                if (value != 0) magnitude[magnitude.Length - 1 - word] |= 1u << bit; 
        
                // сбросить значение бита
                else magnitude[magnitude.Length - 1 - word] &= ~(1u << bit); 
            }
        }
        // изменить значение бита
        public void Invert(int index) 
        { 
            // определить позицию бита
            int word = (m - 1 - index) / 32; int bit = (m - 1 - index) % 32; 
        
            // установить значение бита
            magnitude[magnitude.Length - 1 - word] ^= 1u << bit; 
        }
        // завершить преобразование
        public Vector ToVector() { return new Vector(magnitude, m); }
    }
}
