namespace Aladdin.CAPI.ANSI.X957
{
	///////////////////////////////////////////////////////////////////////////
	// Параметры ключей DSA
	///////////////////////////////////////////////////////////////////////////
	public interface IParameters : CAPI.IParameters
	{
		Math.BigInteger P	{ get; }		// параметр P
		Math.BigInteger Q	{ get; }		// параметр Q
		Math.BigInteger G	{ get; }		// параметр G
	}
}
