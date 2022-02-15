package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_VERSION {
//		CK_BYTE major;
//		CK_BYTE minor;
// } CK_VERSION;
///////////////////////////////////////////////////////////////////////////////
public class CK_VERSION
{
    // конструктор
	public CK_VERSION(byte major, byte minor)
	{
        // сохранить переданные параметры
		this.major = major; this.minor = minor;
	}
	// <B>PKCS#11:</B>
	// <PRE>
	// CK_BYTE major;
	// </PRE>
	public final byte major; /* integer portion of version number */

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_BYTE minor;
	// </PRE>
	public final byte minor; /* 1/100ths portion of version number */
}
