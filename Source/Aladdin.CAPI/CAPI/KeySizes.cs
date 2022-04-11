using System; 
using System.Collections.Generic; 

namespace Aladdin.CAPI
{
    ////////////////////////////////////////////////////////////////////////////////
    // Размеры поддерживаемых ключей
    ////////////////////////////////////////////////////////////////////////////////
    public static class KeySizes 
    {
        // произвольный размер ключей
        public static readonly int[] Unrestricted = null; 

        // создать диапазон значений
        public static int[] Range(int minSize, int maxSize, int increment)
        {
            // выделить буфер требуемого размера
            int[] keySizes = new int[(maxSize - minSize) / increment + 1]; 
        
            // для всех допустимых размеров
            for (int i = 0; i < keySizes.Length; i++)
            {
                // вычислить размер
                keySizes[i] = minSize + i * increment; 
            }
            return keySizes; 
        }
        // создать диапазон значений
        public static int[] Range(int minSize, int maxSize) 
        { 
            // создать диапазон значений
            return Range(minSize, maxSize, 1); 
        }
        // создать диапазон значений
        public static int[] Range(int size) { return new int[] { size }; }
    
        // признак принадлежности размера
        public static bool Contains(int[] keySizes, int keySize)
        {
            // проверить наличие фиксированных размеров
            if (keySizes == KeySizes.Unrestricted) return true; 
        
            // для всех допустимых размеров
            foreach (int size in keySizes)
            {
                // проверить совпадение размера
                if (size == keySize) return true; 
            }
            return false; 
        }
        // выбрать ближайший больший размер
        public static int Ceil(int[] keySizes, int keySize)
        {
            // проверить наличие фиксированных размеров
            if (keySizes == KeySizes.Unrestricted) return keySize; 
        
            // проверить наличие размеров
            if (keySizes.Length == 0) return 0; int size = keySizes[0]; 
        
            // проверить завершение действий
            if (size == keySize) return keySize; 

            // для всех допустимых размеров
            for (int i = 1; i < keySizes.Length; i++)
            {
                // проверить завершение действий
                if (keySizes[i] == keySize) return keySize; 
            
                // для большего размера
                if (keySizes[i] > keySize)
                {
                    // сохранить больший размер
                    if (size < keySize) size = keySizes[i]; 
                
                    // сохранить ближайший больший размер
                    else if (keySizes[i] < size) size = keySizes[i]; 
                }
                // сохранить ближайший меньший размер
                else if (size < keySizes[i]) size = keySizes[i]; 
            }
            return size; 
        }
    }
}
