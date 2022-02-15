package aladdin.capi;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Фабрика создания генераторов случайных данных
///////////////////////////////////////////////////////////////////////////
public class ConfigRandFactory extends RefObject implements IRandFactory
{
    // фабрика создания генераторов случайных данных
    private final IRandFactory randFactory; private final boolean critical; 

    // конструктор
    public ConfigRandFactory(IRandFactory randFactory, boolean critical)
    {
        // сохранить переданные параметры
        this.randFactory = RefObject.addRef(randFactory); this.critical = critical; 
    }
    // освободить используемые ресурсы
    @Override protected void onClose() throws IOException  
    {
        // освободить используемые ресурсы
        RefObject.release(randFactory); super.onClose(); 
    }
    // создать генератор случайных данных
    @Override public IRand createRand(Object window) throws IOException
    {
        // создать генератор случайных данных
        try { return randFactory.createRand(window); }

        // обработать возможную ошибку
        catch (Throwable e) { if (critical) throw e; return null; }
    }
}
