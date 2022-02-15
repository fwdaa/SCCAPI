package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_RC5_PARAMS {
//   CK_ULONG      ulWordsize;  
//   CK_ULONG      ulRounds;    
// } CK_RC5_PARAMS;
///////////////////////////////////////////////////////////////////////////////
public class CK_RC5_PARAMS 
{
    // конструктор
    public CK_RC5_PARAMS(int wordsize, int rounds)
    {
        this.wordsize  = wordsize;  // wordsize in bits
        this.rounds    = rounds;    // number of rounds
    }
    public final int wordsize;      // wordsize in bits
    public final int rounds;        // number of rounds
};
