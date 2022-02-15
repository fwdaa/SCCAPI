using System;

namespace Aladdin.CAPI.ANSI.RSA
{
    ///////////////////////////////////////////////////////////////////////////////
    // Параметры RSA
    ///////////////////////////////////////////////////////////////////////////////
    public interface IParameters : CAPI.IParameters
    {
        // размер модуля в битах и величина открытой экспоненты
        int KeySize { get; } Math.BigInteger PublicExponent { get; } 
    }
}
