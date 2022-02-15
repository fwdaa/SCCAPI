package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_RC5_CBC_PARAMS {
//   CK_ULONG      ulWordsize;  
//   CK_ULONG      ulRounds;    
//   CK_BYTE_PTR   pIv;         
//   CK_ULONG      ulIvLen;     
// } CK_RC5_CBC_PARAMS;
///////////////////////////////////////////////////////////////////////////////
public class CK_RC5_CBC_PARAMS 
{
    // конструктор
    public CK_RC5_CBC_PARAMS(int wordsize, int rounds, byte[] iv)
    {
        this.wordsize = wordsize;   // wordsize in bits
        this.rounds   = rounds;     // number of rounds
        this.iv       = iv;         // pointer to IV
    }
    public final int    wordsize;   // wordsize in bits
    public final int    rounds;     // number of rounds
    public final byte[] iv;         // pointer to IV
}
