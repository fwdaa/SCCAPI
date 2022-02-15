package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_SESSION_INFO {
//		CK_SLOT_ID slotID;
//		CK_STATE state;
//		CK_FLAGS flags;
//		CK_ULONG ulDeviceError;
// } CK_SESSION_INFO;
public class CK_SESSION_INFO
{
    // конструктор
	public CK_SESSION_INFO(long slotID, long state, long flags, long ulDeviceError)
	{
        // сохранить переданные параметры
		this.slotID        = slotID;
		this.state         = state;
		this.flags         = flags;
		this.ulDeviceError = ulDeviceError;
	}
	// <B>PKCS#11:</B>
	// <PRE>
	// CK_SLOT_ID slotID;
	//</PRE>
	public final long slotID;

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_STATE state;
	// </PRE>
	public final long state;

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_FLAGS flags;
	// </PRE>
	public final long flags; /* see below */

	// <B>PKCS#11 (was changed from CK_USHORT
	// to CK_ULONG for v2.0):</B>
	// <PRE>
	// CK_ULONG ulDeviceError;
	// </PRE>
	public final long ulDeviceError; /* device-dependent error code */
}
