namespace Aladdin.CAPI.PBE
{
    ///////////////////////////////////////////////////////////////////////////////
    // Указание параметров парольной защиты
    ///////////////////////////////////////////////////////////////////////////////
    public interface IPBECultureFactory : IRefObject 
    {
        // получить параметры парольной защиты
        PBECulture GetCulture(object window, string keyOID); 
    }
}
