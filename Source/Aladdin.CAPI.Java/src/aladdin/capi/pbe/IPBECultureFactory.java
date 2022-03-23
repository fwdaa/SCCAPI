package aladdin.capi.pbe;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////////
// Указание параметров парольной защиты
///////////////////////////////////////////////////////////////////////////////
public interface IPBECultureFactory extends IRefObject 
{
    // получить параметры парольной защиты
    PBECulture getCulture(Object window, String keyOID) throws IOException; 
}
