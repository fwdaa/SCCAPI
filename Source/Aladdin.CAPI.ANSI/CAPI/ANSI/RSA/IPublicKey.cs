namespace Aladdin.CAPI.ANSI.RSA
{
	///////////////////////////////////////////////////////////////////////////
	// Открытый ключ алгоритма RSA
	///////////////////////////////////////////////////////////////////////////
	public interface IPublicKey : CAPI.IPublicKey
	{
		Math.BigInteger Modulus          { get; }		// параметр N
		Math.BigInteger PublicExponent   { get; }		// параметр E
	}
}
