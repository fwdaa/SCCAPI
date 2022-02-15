package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_TOKEN_INFO {
//		CK_UTF8CHAR label[32];
//		CK_UTF8CHAR manufacturerID[32];
//		CK_UTF8CHAR model[16];
//		CK_CHAR serialNumber[16];
//		CK_FLAGS flags;
//		CK_ULONG ulMaxSessionCount;
//		CK_ULONG ulSessionCount;
//		CK_ULONG ulMaxRwSessionCount;
//		CK_ULONG ulRwSessionCount;
//		CK_ULONG ulMaxPinLen;
//		CK_ULONG ulMinPinLen;
//		CK_ULONG ulTotalPublicMemory;
//		CK_ULONG ulFreePublicMemory;
//		CK_ULONG ulTotalPrivateMemory;
//		CK_ULONG ulFreePrivateMemory;
//		CK_VERSION hardwareVersion;
//		CK_VERSION firmwareVersion;
//		CK_CHAR utcTime[16];
// } CK_TOKEN_INFO;
///////////////////////////////////////////////////////////////////////////////
public class CK_TOKEN_INFO 
{
    // конструктор
	public CK_TOKEN_INFO(byte[] label, byte[] manufacturerID, byte[] model,
		char[] serialNo, long flags, int sessionMax, int session,
		int rwSessionMax, int rwSession, int pinLenMax, int pinLenMin,
		int totalPubMem, int freePubMem, int totalPrivMem, int freePrivMem,
		CK_VERSION hwVer, CK_VERSION fwVer, char[] utcTime)
	{
        // сохранить переданные параметры
		this.label                = label;
		this.manufacturerID       = manufacturerID;
		this.model                = model;
		this.serialNumber         = serialNo;
		this.flags                = flags;
		this.ulMaxSessionCount    = sessionMax;
		this.ulSessionCount       = session;
		this.ulMaxRwSessionCount  = rwSessionMax;
		this.ulRwSessionCount     = rwSession;
		this.ulMaxPinLen          = pinLenMax;
		this.ulMinPinLen          = pinLenMin;
		this.ulTotalPublicMemory  = totalPubMem;
		this.ulFreePublicMemory   = freePubMem;
		this.ulTotalPrivateMemory = totalPrivMem;
		this.ulFreePrivateMemory  = freePrivMem;
		this.hardwareVersion      = hwVer;
		this.firmwareVersion      = fwVer;
		this.utcTime              = utcTime;
	}
	// must be blank padded and only the first 32 chars will be used<p>
	// <B>PKCS#11 (have been changed from
	// CK_CHAR to CK_UTF8CHAR for v2.11):</B>
	// <PRE>
	// CK_UTF8CHAR label[32];
	// </PRE>
	public final byte[] label; /* blank padded */
	// must be blank padded and only the first 32 chars will be used<p>
	// <B>PKCS#11 (have been changed from
	// CK_CHAR to CK_UTF8CHAR for v2.11):</B>
	// <PRE>
	// CK_UTF8CHAR manufacturerID[32];
	// </PRE>
	public final byte[] manufacturerID; /* blank padded */

	// must be blank padded and only the first 16 chars will be used<p>
	// <B>PKCS#11 (have been changed from
	// CK_CHAR to CK_UTF8CHAR for v2.11):</B>
	// <PRE>
	// CK_UTF8CHAR model[16];
	// </PRE>
	public final byte[] model; /* blank padded */

	// must be blank padded and only the first 16 chars will be used<p>
	// <B>PKCS#11:</B>
	// <PRE>
	// CK_CHAR serialNumber[16];
	// </PRE>
	public final char[] serialNumber; /* blank padded */

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_FLAGS flags;
	// </PRE>
	public final long flags; /* see below */

	// <B>PKCS#11 (have been changed from
	// CK_USHORT to CK_ULONG for v2.0):</B>
	// <PRE>
	// CK_ULONG ulMaxSessionCount;
	// </PRE>
	public final int ulMaxSessionCount; /* max open sessions */
	
	// <B>PKCS#11 (have been changed from
	// CK_USHORT to CK_ULONG for v2.0):</B>
	// <PRE>
	// CK_ULONG ulSessionCount;
	// </PRE>
	public final int ulSessionCount; /* sess. now open */
	
	// <B>PKCS#11 (have been changed from
	// CK_USHORT to CK_ULONG for v2.0):</B>
	// <PRE>
	// CK_ULONG ulMaxRwSessionCount;
	// </PRE>
	//
	public final int ulMaxRwSessionCount; /* max R/W sessions */
	
	// <B>PKCS#11 (have been changed from
	// CK_USHORT to CK_ULONG for v2.0):</B>
	// <PRE>
	// CK_ULONG ulRwSessionCount;
	// </PRE>
	public final int ulRwSessionCount; /* R/W sess. now open */

	// <B>PKCS#11 (have been changed from
	// CK_USHORT to CK_ULONG for v2.0):</B>
	// <PRE>
	// CK_ULONG ulMaxPinLen;
	// </PRE>
	public final int ulMaxPinLen; /* in bytes */

	// <B>PKCS#11 (have been changed from
	// CK_USHORT to CK_ULONG for v2.0):</B>
	// <PRE>
	// CK_ULONG ulMinPinLen;
	// </PRE>
	public final int ulMinPinLen; /* in bytes */

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_ULONG ulTotalPublicMemory;
	// </PRE>
	public final int ulTotalPublicMemory; /* in bytes */

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_ULONG ulFreePublicMemory;
	// </PRE>
	public final int ulFreePublicMemory; /* in bytes */

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_ULONG ulTotalPrivateMemory;
	// </PRE>
	public final int ulTotalPrivateMemory; /* in bytes */

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_ULONG ulFreePrivateMemory;
	// </PRE>
	public final int ulFreePrivateMemory; /* in bytes */

	// <B>PKCS#11 (new for v2.0):</B>
	// <PRE>
	// CK_VERSION hardwareVersion;
	// </PRE>
	public final CK_VERSION hardwareVersion; /* version of hardware */

	// <B>PKCS#11 (new for v2.0):</B>
	// <PRE>
	// CK_VERSION firmwareVersion;
	// </PRE>
	public final CK_VERSION firmwareVersion; /* version of firmware */

	// only the first 16 chars will be used
	// <B>PKCS#11 (new for v2.0):</B>
	// <PRE>
	// CK_CHAR utcTime[16];
	// </PRE>
	public final char[] utcTime; /* time */
}
