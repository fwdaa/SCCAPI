package aladdin.capi;

////////////////////////////////////////////////////////////////////////////////
// Размеры поддерживаемых ключей
////////////////////////////////////////////////////////////////////////////////
public class KeySizes 
{
    // произвольный размер ключей
    public static final int[] UNRESTRICTED = null; 
    
    // создать диапазон значений
    public static int[] range(int minSize, int maxSize, int increment)
    {
        // выделить буфер требуемого размера
        int[] keySizes = new int[(maxSize - minSize) / increment + 1]; 
        
        // для всех допустимых размеров
        for (int i = 0; i < keySizes.length; i++)
        {
            // вычислить размер
            keySizes[i] = minSize + i * increment; 
        }
        return keySizes; 
    }
    // создать диапазон значений
    public static int[] range(int minSize, int maxSize) 
    { 
        // создать диапазон значений
        return range(minSize, maxSize, 1); 
    }
    // создать диапазон значений
    public static int[] range(int size) { return new int[] { size }; }
    
    // признак принадлежности размера
    public static boolean contains(int[] keySizes, int keySize)
    {
        // проверить наличие фиксированных размеров
        if (keySizes == KeySizes.UNRESTRICTED) return true; 
        
        // для всех допустимых размеров
        for (int size : keySizes)
        {
            // проверить совпадение размера
            if (size == keySize) return true; 
        }
        return false; 
    }
    // выбрать ближайший больший размер
    public static int ceil(int[] keySizes, int keySize)
    {
        // проверить наличие фиксированных размеров
        if (keySizes == KeySizes.UNRESTRICTED) return keySize; 
        
        // проверить наличие размеров
        if (keySizes.length == 0) return 0; int size = keySizes[0]; 
        
        // проверить завершение действий
        if (size == keySize) return keySize; 

        // для всех допустимых размеров
        for (int i = 1; i < keySizes.length; i++)
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
