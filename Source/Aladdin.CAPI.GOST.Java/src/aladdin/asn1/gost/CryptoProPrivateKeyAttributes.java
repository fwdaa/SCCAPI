package aladdin.asn1.gost;

///////////////////////////////////////////////////////////////////////////////
//  GostPrivateKeyAttributes ::= BIT STRING {
//      pkaExportable(0), pkaUserProtect(1), pkaExchange(2), pkaEphemeral(3), pkaNonCachable(4)
//  }
///////////////////////////////////////////////////////////////////////////////
public final class CryptoProPrivateKeyAttributes
{
    public static final long NONE			= 0x0000L;  
	public static final long EXPORTABLE     = 0x0001L;  
	public static final long USER_PROTECT	= 0x0002L; 
	public static final long EXCHANGE		= 0x0004L;
	public static final long EPHEMERAL      = 0x0008L;
	public static final long NON_CACHEBLE	= 0x0010L;
}
