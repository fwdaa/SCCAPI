package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_GOSTR3410_KEY_WRAP_PARAMS {
// 	CK_BYTE_PTR      pWrapOID;
// 	CK_ULONG         ulWrapOIDLen;
// 	CK_BYTE_PTR      pUKM;
// 	CK_ULONG         ulUKMLen;
// 	CK_OBJECT_HANDLE hKey;
// } CK_GOSTR3410_KEY_WRAP_PARAMS;
///////////////////////////////////////////////////////////////////////////////
public class CK_GOSTR3410_KEY_WRAP_PARAMS 
{
    // конструктор
    public CK_GOSTR3410_KEY_WRAP_PARAMS(byte[] wrapOID, byte[] ukm, long hPublicKey)
    {
        // сохранить переданные параметры
        this.wrapOID = wrapOID; this.ukm = ukm; this.hPublicKey = hPublicKey; 
    }
 	public final byte[] wrapOID;      // параметры шифрования при обмене
 	public final byte[] ukm;          // случайные данные
 	public final long   hPublicKey;   // идентификатор открытого ключа
}
