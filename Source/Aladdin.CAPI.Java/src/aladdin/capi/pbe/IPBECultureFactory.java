package aladdin.capi.pbe;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Указание параметров парольной защиты
///////////////////////////////////////////////////////////////////////////////
public interface IPBECultureFactory
{
    // получить параметры парольной защиты
    PBECulture getPBECulture(Object window, String keyOID) throws IOException; 
}
