package aladdin.math;

////////////////////////////////////////////////////////////////////////////
// Создание многочлена
////////////////////////////////////////////////////////////////////////////
public final class PolynomBuilder
{
    // коэффициенты вектора
    private final int[] magnitude; 

    // конструктор
    public PolynomBuilder(int m) 
    {
        // создать список коэффициентов вектора
        magnitude = new int[(m + 31) / 32]; 
    }
    // получить значение бита
    public final int get(int index)
    {
        // определить позицию бита
        int word = index / 32; int bit = index % 32; 
        
        // вернуть значение бита
        return ((magnitude[magnitude.length - 1 - word] & (1 << bit)) != 0) ? 1 : 0; 
    }
    // установить значение бита
    public final void set(int index, int value)
    {
        // определить позицию бита
        int word = index / 32; int bit = index % 32; 

        // установить значение бита
        if (value != 0) magnitude[magnitude.length - 1 - word] |= 1 << bit; 
            
        // сбросить значение бита
        else magnitude[magnitude.length - 1 - word] &= ~(1 << bit); 
    }
    // изменить значение бита
    public final void invert(int index) 
    { 
        // определить позицию бита
        int word = index / 32; int bit = index % 32; 
            
        // установить значение бита
        magnitude[magnitude.length - 1 - word] ^= 1 << bit; 
    }
    // завершить преобразование
    public final Polynom toPolynom() { return new Polynom(magnitude); }
}
