namespace Aladdin.CAPI.ANSI.X942
{
	///////////////////////////////////////////////////////////////////////////
	// Параметры ключей DH
	///////////////////////////////////////////////////////////////////////////
	public interface IParameters : CAPI.IParameters
	{
		Math.BigInteger P	{ get; }		// параметр P
		Math.BigInteger Q	{ get; }		// параметр Q
		Math.BigInteger G	{ get; }		// параметр G
	}
}
