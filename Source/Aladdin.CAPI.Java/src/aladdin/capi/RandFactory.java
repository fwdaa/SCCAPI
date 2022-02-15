package aladdin.capi;
import aladdin.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Фабрика создания генераторов случайных данных
///////////////////////////////////////////////////////////////////////////
public class RandFactory extends RefObject implements IRandFactory 
{
    // конструктор
    public RandFactory(IRand rand)
     
        // сохранить переданные параметры 
        { this.rand = RefObject.addRef(rand); } private final IRand rand; 
     
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException
    {
        // вызвать базовую функцию
        RefObject.release(rand); super.onClose();
    }
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) throws IOException
    { 
        // вернуть генератор случайных данных
        return RefObject.addRef(rand);  
    } 
}
