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
    }
}
