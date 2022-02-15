package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_MECHANISM_INFO {
//		CK_ULONG ulMinKeySize;
//		CK_ULONG ulMaxKeySize;
//		CK_FLAGS flags;
// } CK_MECHANISM_INFO;
///////////////////////////////////////////////////////////////////////////////
public class CK_MECHANISM_INFO
{
    // конструктор
	public CK_MECHANISM_INFO(int minKeySize, int maxKeySize, long flags)
	{
        // сохранить переданные параметры
		this.ulMinKeySize = minKeySize;
		this.ulMaxKeySize = maxKeySize;
		this.flags        = flags;
	}
	// <B>PKCS#11:</B>
	// <PRE>
	// CK_ULONG ulMinKeySize;
	// </PRE>
	public final int ulMinKeySize;

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_ULONG ulMaxKeySize;
	// </PRE>
	public final int ulMaxKeySize;

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_FLAGS flags;
	// </PRE>
	public final long flags;
}
