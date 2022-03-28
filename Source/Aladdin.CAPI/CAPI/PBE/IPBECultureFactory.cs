namespace Aladdin.CAPI.PBE
{
    ///////////////////////////////////////////////////////////////////////////////
    // Указание параметров парольной защиты
    ///////////////////////////////////////////////////////////////////////////////
    public interface IPBECultureFactory
    {
        // получить параметры парольной защиты
        PBECulture GetPBECulture(object window, string keyOID); 
    }
}
