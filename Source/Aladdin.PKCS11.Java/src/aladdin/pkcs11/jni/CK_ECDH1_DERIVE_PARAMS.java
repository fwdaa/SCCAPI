package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_ECDH1_DERIVE_PARAMS {
//    CK_EC_KDF_TYPE kdf;
//    CK_ULONG ulSharedDataLen;
//    CK_BYTE_PTR pSharedData;
//    CK_ULONG ulPublicDataLen;
//    CK_BYTE_PTR pPublicData;
// } CK_ECDH1_DERIVE_PARAMS;///////////////////////////////////////////////////////////////////////////////
public class CK_ECDH1_DERIVE_PARAMS 
{
    // конструктор
	public CK_ECDH1_DERIVE_PARAMS(long kdf, byte[] sharedData, byte[] publicData)
	{
        // сохранить переданные параметры
		this.kdf = kdf; this.sharedData = sharedData; this.publicData = publicData; 
	}
    public final long   kdf;        // key derivation function used on the shared secret value
    public final byte[] sharedData; // some data shared between the two parties
    public final byte[] publicData; // pointer to other party’s X9.42 Diffie-Hellman public key value
}
