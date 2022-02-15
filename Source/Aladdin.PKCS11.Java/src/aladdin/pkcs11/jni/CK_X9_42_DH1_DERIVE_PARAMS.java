package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_X9_42_DH1_DERIVE_PARAMS {
//   CK_X9_42_DH_KDF_TYPE kdf;
//   CK_ULONG ulOtherInfoLen;
//   CK_BYTE_PTR pOtherInfo;
//   CK_ULONG ulPublicDataLen;
//   CK_BYTE_PTR pPublicData;
//} CK_X9_42_DH1_DERIVE_PARAMS;
///////////////////////////////////////////////////////////////////////////////
public class CK_X9_42_DH1_DERIVE_PARAMS 
{
    // конструктор
	public CK_X9_42_DH1_DERIVE_PARAMS(long kdf, byte[] otherInfo, byte[] publicData)
	{
        // сохранить переданные параметры
		this.kdf = kdf; this.otherInfo = otherInfo; this.publicData = publicData; 
	}
    public final long   kdf;        // key derivation function used on the shared secret value
    public final byte[] otherInfo;  // some data shared between the two parties
    public final byte[] publicData; // pointer to other party’s X9.42 Diffie-Hellman public key value
}
