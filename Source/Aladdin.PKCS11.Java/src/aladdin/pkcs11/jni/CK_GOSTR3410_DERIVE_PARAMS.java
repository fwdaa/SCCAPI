package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_GOSTR3410_DERIVE_PARAMS {
// 	CK_EC_KDF_TYPE	kdf;
// 	CK_BYTE_PTR		pPublicData;
// 	CK_ULONG		ulPublicDataLen;
// 	CK_BYTE_PTR		pUKM;
// 	CK_ULONG		ulUKMLen;
// } CK_GOSTR3410_DERIVE_PARAMS;
///////////////////////////////////////////////////////////////////////////////
public class CK_GOSTR3410_DERIVE_PARAMS 
{
    // конструктор
    public CK_GOSTR3410_DERIVE_PARAMS(long kdf, byte[] publicData, byte[] ukm)
    {
        // сохранить переданные параметры
        this.kdf = kdf; this.publicData = publicData; this.ukm = ukm; 
    }
    public final long    kdf;         // тип диверсификации
    public final byte[]  publicData;  // значение открытого ключа
    public final byte[]  ukm;         // случайные данные
}
