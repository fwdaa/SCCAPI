namespace Aladdin.CAPI.ANSI.RSA
{
	///////////////////////////////////////////////////////////////////////////
	// Личный ключ алгоритма RSA
	///////////////////////////////////////////////////////////////////////////
	public interface IPrivateKey : CAPI.IPrivateKey
	{
		Math.BigInteger Modulus			{ get; }		// параметр N	
		Math.BigInteger PublicExponent	{ get; }		// параметр E
		Math.BigInteger PrivateExponent	{ get; }		// параметр D
		Math.BigInteger PrimeP			{ get; }		// параметр P
		Math.BigInteger PrimeQ			{ get; }		// параметр Q
		Math.BigInteger PrimeExponentP	{ get; }		// параметр D (mod P-1)
		Math.BigInteger PrimeExponentQ	{ get; }		// параметр D (mod Q-1)
		Math.BigInteger CrtCoefficient	{ get; }		// параметр Q^{-1}(mod P)
	}										 
}
