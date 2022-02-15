namespace Aladdin.CAPI.GOST.GOSTR3410
{
    ///////////////////////////////////////////////////////////////////////////
    // Параметры DH
    ///////////////////////////////////////////////////////////////////////////
    public interface IDHParameters : CAPI.IParameters
    {
	    Math.BigInteger              P                    { get; } // параметр P
	    Math.BigInteger              Q                    { get; } // параметр Q
	    Math.BigInteger              G                    { get; } // параметр A
        ASN1.ISO.AlgorithmIdentifier ValidationParameters { get; } // параметры проверки
    }
}
