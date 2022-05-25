package aladdin.capi.rnd;
import aladdin.capi.*; 
import aladdin.*; 

///////////////////////////////////////////////////////////////////////////
// Генератор нулевых данных
///////////////////////////////////////////////////////////////////////////
public final class Zero extends RefObject implements IRand
{
    // конструктор
    public Zero(Object window) 
            
        // сохранить переданные параметры
        { this.window = window; } private final Object window; 

    // изменить окно для генератора
    @Override public IRand createRand(Object window) 
    { 
        // изменить окно для генератора
        return Rand.rebind(this, window); 
    } 
    // описатель окна
    @Override public Object window() { return window; } 

    // сгенерировать случайные данные
    @Override public void generate(byte[] data, int dataOff, int dataLen)
    {
        // указать нулевые данные
        for (int i = 0; i < dataLen; i++) data[dataOff + i] = 0; 
    }
}
