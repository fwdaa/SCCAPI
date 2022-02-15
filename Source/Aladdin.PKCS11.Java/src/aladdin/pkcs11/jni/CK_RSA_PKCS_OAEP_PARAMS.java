package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_RSA_PKCS_OAEP_PARAMS {
//  CK_MECHANISM_TYPE hashAlg;
//  CK_RSA_PKCS_MGF_TYPE mgf;
//  CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
//  CK_VOID_PTR pSourceData;
//  CK_ULONG ulSourceDataLen;
// } CK_RSA_PKCS_OAEP_PARAMS;
///////////////////////////////////////////////////////////////////////////////
public class CK_RSA_PKCS_OAEP_PARAMS 
{
    // конструктор
    public CK_RSA_PKCS_OAEP_PARAMS(long hashAlg, long mgf, byte[] sourceData)
    {
        // сохранить переданные параметры
        this.hashAlg    = hashAlg;     // mechanism ID of the message digest algorithm
        this.mgf        = mgf;         // mask generation function to use on the encoded block
        this.sourceData = sourceData;  // data used as the input for the encoding parameter source
    }
    public final long   hashAlg;       // mechanism ID of the message digest algorithm
    public final long   mgf;           // mask generation function to use on the encoded block
    public final byte[] sourceData;    // data used as the input for the encoding parameter source
}
