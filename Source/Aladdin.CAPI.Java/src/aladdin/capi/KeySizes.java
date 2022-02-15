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
}
