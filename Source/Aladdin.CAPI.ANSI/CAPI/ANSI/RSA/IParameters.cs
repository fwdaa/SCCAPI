namespace Aladdin.CAPI.ANSI.RSA
{
    ///////////////////////////////////////////////////////////////////////////////
    // Параметры RSA
    ///////////////////////////////////////////////////////////////////////////////
    public interface IParameters : IKeySizeParameters
    {
        // размер модуля в битах и величина открытой экспоненты
        Math.BigInteger PublicExponent { get; } 
    }
}
