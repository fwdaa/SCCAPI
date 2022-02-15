package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_MECHANISM {
//		CK_MECHANISM_TYPE mechanism;
//		CK_VOID_PTR pParameter;
//		CK_ULONG ulParameterLen;
// } CK_MECHANISM;
///////////////////////////////////////////////////////////////////////////////
public class CK_MECHANISM
{
    // конструктор
	public CK_MECHANISM(long mechanism, Object parameter)
	{
        // сохранить переданные параметры
		this.mechanism = mechanism; this.parameter = parameter;
	}
    // конструктор
	public CK_MECHANISM(long mechanism) { this(mechanism, null); }
    
	// <B>PKCS#11:</B>
	// <PRE>
	// CK_MECHANISM_TYPE mechanism;
	// </PRE>
	public final long mechanism;

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_VOID_PTR pParameter;
	// CK_ULONG ulParameterLen;
	// </PRE>
	public final Object parameter;
}
