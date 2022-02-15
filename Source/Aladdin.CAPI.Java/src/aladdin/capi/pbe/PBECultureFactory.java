package aladdin.capi.pbe;
import aladdin.*; 
import aladdin.capi.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Указание параметров парольной защиты
///////////////////////////////////////////////////////////////////////////////
public abstract class PBECultureFactory extends RefObject implements IPBECultureFactory 
{
    // получить параметры парольной защиты
    @Override public abstract PBECulture getCulture(Object window, String keyOID); 

    ///////////////////////////////////////////////////////////////////////////
    // Фиксированные параметры парольной защиты
    ///////////////////////////////////////////////////////////////////////////
    public static class Fixed extends PBECultureFactory
    {
        // конструктор
        public Fixed(PBECulture culture)

            // сохранить переданные параметры
            { this.culture = culture; } private final PBECulture culture; 

        // получить параметры парольной защиты
        @Override public PBECulture getCulture(Object window, String keyOID) { return culture; }
    }
    ///////////////////////////////////////////////////////////////////////////
    // Параметры парольной защиты по умолчанию
    ///////////////////////////////////////////////////////////////////////////
    public static class Default extends PBECultureFactory
    {
        // фабрика создания алгоритмов и параметры парольной защиты
        private final Factory factory; private final PBEParameters parameters;
        
        // конструктор
        public Default(Factory factory, PBEParameters parameters)
        {
            // сохранить переданные параметры
            this.factory = RefObject.addRef(factory); this.parameters = parameters; 
        }
        // деструктор
        @Override protected void onClose() throws IOException
        {
            // освободить используемые ресурсы
            RefObject.release(factory); super.onClose();
        }
        // получить параметры парольной защиты
        @Override public PBECulture getCulture(Object window, String keyOID) 
        { 
            // получить параметры парольной защиты
            return factory.getCulture(parameters, keyOID); 
        }
    }
}
