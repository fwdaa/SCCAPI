namespace Aladdin.CAPI
{
    ///////////////////////////////////////////////////////////////////////////
    // Фабрика создания параметров
    ///////////////////////////////////////////////////////////////////////////
    public interface IParametersFactory
    {
        // получить параметры алгоритма
        IParameters GetParameters(IRand rand, string keyOID, KeyUsage keyUsage); 
    }
}
