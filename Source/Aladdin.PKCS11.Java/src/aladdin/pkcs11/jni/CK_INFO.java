package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_INFO {
// 		CK_VERSION cryptokiVersion;
// 		CK_UTF8CHAR manufacturerID[32];
// 		CK_FLAGS flags;&nbsp;
// 		CK_UTF8CHAR libraryDescription[32];
// 		CK_VERSION libraryVersion;
// } CK_INFO;
///////////////////////////////////////////////////////////////////////////////
public class CK_INFO
{
    // конструктор
	public CK_INFO(CK_VERSION cryptoVer, byte[] vendor, long flags,
		byte[] libDesc, CK_VERSION libVer)
	{
        // сохранить переданные параметры
		this.cryptokiVersion    = cryptoVer;
		this.manufacturerID     = vendor;
		this.flags              = flags;
		this.libraryDescription = libDesc;
		this.libraryVersion     = libVer;
	}
	// Cryptoki interface version number<p>
	// <B>PKCS#11:</B>
	// <PRE>
	// CK_VERSION cryptokiVersion;
	// </PRE>
	public final CK_VERSION cryptokiVersion;

	// ID of the Cryptoki library manufacturer. must be blank
	// padded - only the first 32 chars will be used<p>
	// <B>PKCS#11:</B>
	// <PRE>
	// CK_UTF8CHAR manufacturerID[32];
	// </PRE>
	public final byte[] manufacturerID;

	// bit flags reserved for future versions. must be zero<p>
	// <B>PKCS#11:</B>
	// <PRE>
	// CK_FLAGS flags;
	// </PRE>
	public final long flags;

	// must be blank padded - only the first 32 chars will be used<p>
	// <B>PKCS#11 (new for v2.0):</B>
	// <PRE>
	// CK_UTF8CHAR libraryDescription[32];
	// </PRE>
	public final byte[] libraryDescription;

	// Cryptoki library version number<p>
	// <B>PKCS#11 (new for v2.0):</B>
	// <PRE>
	// CK_VERSION libraryVersion;
	// </PRE>
	public final CK_VERSION libraryVersion;
}
