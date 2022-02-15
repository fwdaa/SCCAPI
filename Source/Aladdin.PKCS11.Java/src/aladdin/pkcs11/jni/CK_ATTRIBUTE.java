package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_ATTRIBUTE {
//		CK_ATTRIBUTE_TYPE type;
//		CK_VOID_PTR pValue;
//		CK_ULONG ulValueLen;
// } CK_ATTRIBUTE;
///////////////////////////////////////////////////////////////////////////////
public class CK_ATTRIBUTE
{
    // конструктор
	public CK_ATTRIBUTE(long type, Object value)
	{
        // сохранить переданные параметры
		this.type = type; this.value = value;
        
        // получить класс значения
        this.valueClass = value.getClass();
	}
    // конструктор
	public CK_ATTRIBUTE(long type, Class<?> valueClass) 
    { 
        // сохранить переданные параметры
		this.type = type; this.valueClass = valueClass; this.value = null; 
    }
	// <B>PKCS#11:</B>
	// <PRE>
	// CK_ATTRIBUTE_TYPE type;
	// </PRE>
	public final long type; 
    
	// <B>PKCS#11:</B>
	// <PRE>
	// CK_VOID_PTR pValue;
	// CK_ULONG ulValueLen;
	// </PRE>
	public final Class<?> valueClass; public final Object value;
}
