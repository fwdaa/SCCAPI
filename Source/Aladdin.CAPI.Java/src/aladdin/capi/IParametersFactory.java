package aladdin.capi;
import aladdin.*; 
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Фабрика создания параметров
///////////////////////////////////////////////////////////////////////////
public interface IParametersFactory extends IRefObject
{
    // получить параметры алгоритма
    IParameters getParameters(IRand rand, String keyOID, KeyUsage keyUsage) throws IOException; 
}
