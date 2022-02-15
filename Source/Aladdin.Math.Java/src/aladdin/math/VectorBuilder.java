package aladdin.math;

////////////////////////////////////////////////////////////////////////////
// Создание вектора
////////////////////////////////////////////////////////////////////////////
public final class VectorBuilder
{
    // коэффициенты вектора
    private final int[] magnitude; private final int m; 

    // конструктор
    public VectorBuilder(int m) 
    {
        // создать список коэффициентов вектора
        magnitude = new int[(m + 31) / 32]; this.m = m;  
    }
    // получить значение бита
    public final int get(int index)
    {
        // определить позицию бита
        int word = (m - 1 - index) / 32; int bit = (m - 1 - index) % 32; 
        
        // вернуть значение бита
        return ((magnitude[magnitude.length - 1 - word] & (1 << bit)) != 0) ? 1 : 0; 
    }
    // установить значение бита
    public final void set(int index, int value)
    {
        // определить позицию бита
        int word = (m - 1 - index) / 32; int bit = (m - 1 - index) % 32; 

        // установить значение бита
        if (value != 0) magnitude[magnitude.length - 1 - word] |= 1 << bit; 
            
        // сбросить значение бита
        else magnitude[magnitude.length - 1 - word] &= ~(1 << bit); 
    }
    // изменить значение бита
    public final void invert(int index) 
    { 
        // определить позицию бита
        int word = (m - 1 - index) / 32; int bit = (m - 1 - index) % 32; 
            
        // установить значение бита
        magnitude[magnitude.length - 1 - word] ^= 1 << bit; 
    }
    // завершить преобразование
    public final Vector toVector() { return new Vector(magnitude, m); }
}
