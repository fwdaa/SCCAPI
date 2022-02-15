using System;

namespace Aladdin.Math
{
    ////////////////////////////////////////////////////////////////////////////
    // Создание многочлена
    ////////////////////////////////////////////////////////////////////////////
    public sealed class PolynomBuilder
    {
        // коэффициенты вектора
        private UInt32[] magnitude; 

        // конструктор
        public PolynomBuilder(int m) 
        {
            // создать список коэффициентов вектора
            magnitude = new UInt32[(m + 31) / 32]; 
        }
        // получить значение бита
        public int this[int index] 
        { 
            get {
                // определить позицию бита
                int word = index / 32; int bit = index % 32; 
    
                // вернуть значение бита
                return ((magnitude[magnitude.Length - 1 - word] & (1 << bit)) != 0) ? 1 : 0; 
            }
            set { 
                // определить позицию бита
                int word = index / 32; int bit = index % 32; 

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
            int word = index / 32; int bit = index % 32; 
        
            // установить значение бита
            magnitude[magnitude.Length - 1 - word] ^= 1u << bit; 
        }
        // завершить преобразование
        public Polynom ToPolynom() { return new Polynom(magnitude); }
    }
}
