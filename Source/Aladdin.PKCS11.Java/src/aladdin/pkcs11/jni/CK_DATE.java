package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_DATE {
//		CK_CHAR year[4];
//		CK_CHAR month[2];
//		CK_CHAR day[2];
// } CK_DATE;
///////////////////////////////////////////////////////////////////////////////
public class CK_DATE implements Cloneable
{
    // конструктор
	public CK_DATE(char[] year, char[] month, char[] day)
	{
        // сохранить переданные параметры
		this.year = year; this.month = month; this.day = day;
	}
	// <B>PKCS#11:</B>
	// <PRE>
	// CK_CHAR year[4]; - the year ("1900" - "9999")
	// </PRE>
	public final char[] year; /* the year ("1900" - "9999") */

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_CHAR month[2]; - the month ("01" - "12")
	// </PRE>
	public final char[] month; /* the month ("01" - "12") */

	// <B>PKCS#11:</B>
	// <PRE>
	// CK_CHAR day[2]; - the day ("01" - "31")
	// </PRE>
	public final char[] day; /* the day ("01" - "31") */
}
