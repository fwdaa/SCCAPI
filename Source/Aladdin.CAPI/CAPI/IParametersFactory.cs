namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Фабрика создания параметров
    ///////////////////////////////////////////////////////////////////////////
    public interface IParametersFactory
    {
        // получить параметры алгоритма
        IParameters GetKeyParameters(IRand rand, string keyOID, KeyUsage keyUsage); 
    }
}
