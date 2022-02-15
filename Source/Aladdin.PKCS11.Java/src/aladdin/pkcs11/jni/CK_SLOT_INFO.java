package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_SLOT_INFO {
//		CK_UTF8CHAR slotDescription[64];
//		CK_UTF8CHAR manufacturerID[32];
//		CK_FLAGS flags;
//		CK_VERSION hardwareVersion;
//		CK_VERSION firmwareVersion;
// } CK_SLOT_INFO;
///////////////////////////////////////////////////////////////////////////////
public class CK_SLOT_INFO
{
    // конструктор
	public CK_SLOT_INFO(byte[] slotDesc, byte[] vendor,
		long flags, CK_VERSION hwVer, CK_VERSION fwVer)
	{
        // сохранить переданные параметры
		this.slotDescription = slotDesc;
		this.manufacturerID  = vendor;
		this.flags           = flags;
		this.hardwareVersion = hwVer;
		this.firmwareVersion = fwVer;
	}
	// must be blank padded and only the first 64 chars will be used<p>
	// <B>PKCS#11 (have been changed from
	// CK_CHAR to CK_UTF8CHAR for v2.11):</B>
	// <PRE>
	// CK_UTF8CHAR slotDescription[64];
	// </PRE>
	public final byte[] slotDescription;

	// must be blank padded and only the first 32 chars will be used<p>
	// <B>PKCS#11 (have been changed from
	// CK_CHAR to CK_UTF8CHAR for v2.11):</B>
	// <PRE>
	// CK_UTF8CHAR manufacturerID[32];
	// </PRE>
	public final byte[] manufacturerID;

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_FLAGS flags;
	// </PRE>
	public final long flags;

	// version of hardware<p>
	// <B>PKCS#11 (new for v2.0):</B>
	// <PRE>
	// CK_VERSION hardwareVersion;
	// </PRE>
	public final CK_VERSION hardwareVersion;

	// version of firmware<p>
	// <B>PKCS#11 (new for v2.0):</B>
	// <PRE>
	// CK_VERSION firmwareVersion;
	// </PRE>
	public final CK_VERSION firmwareVersion;
}
