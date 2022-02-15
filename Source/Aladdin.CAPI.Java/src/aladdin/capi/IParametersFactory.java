package aladdin.capi;
import aladdin.*; 

///////////////////////////////////////////////////////////////////////////
// Фабрика создания параметров
///////////////////////////////////////////////////////////////////////////
public interface IParametersFactory extends IRefObject
{
    // получить параметры алгоритма
    IParameters getParameters(IRand rand, String keyOID, KeyUsage keyUsage); 
}
