package aladdin.capi.rnd;
import aladdin.capi.*; 
import aladdin.*;

///////////////////////////////////////////////////////////////////////////
// Генератор фиксированных данных
///////////////////////////////////////////////////////////////////////////
public final class Fixed extends RefObject implements IRand
{
    // список значений и номер теукущего значения
    private final byte[][] values; private int index;  

    // конструктор
    public Fixed(byte[]... values) 
    { 
        // сохранить переданные параметры
        super(); this.values = values; index = 0; 
    }
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) 
    {
        // вернуть генератор случайных данных
        return RefObject.addRef(this);  
    }
    // сгенерировать случайные данные
    @Override public void generate(byte[] data, int dataOff, int dataLen) 
    {
        // сгенерировать случайные данные
        byte[] buffer = generate(dataLen); 

        // скопировать сгенерированные данные
        System.arraycopy(buffer, 0, data, dataOff, dataLen); 
    }
    // сгенерировать случайные данные
    public byte[] generate(int dataLen) 
    {
        // проверить совпадение размеров
        if (index >= values.length || values[index].length != dataLen) 
        {
            // при ошибке выбросить исключение
            throw new IllegalArgumentException(); 
        }
        // указать случайные данные
        return values[index++]; 
    }
    public void dump()
    {
        // для всех случайных данных
        for (int i = 0; i < values.length; i++)
        {
            // указать номер случайных данных
            String name = String.format("Random%1$d", i); 

            // вывести случайные данные
            Test.dump(name, values[i]);
        }
    }
    // объект окна
    @Override public Object window() { return null; } 
}
