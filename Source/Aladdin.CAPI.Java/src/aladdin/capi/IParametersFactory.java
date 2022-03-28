package aladdin.capi;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Фабрика создания параметров
///////////////////////////////////////////////////////////////////////////
public interface IParametersFactory 
{
    // получить параметры алгоритма
    IParameters getParameters(IRand rand, String keyOID, KeyUsage keyUsage) throws IOException; 
}
