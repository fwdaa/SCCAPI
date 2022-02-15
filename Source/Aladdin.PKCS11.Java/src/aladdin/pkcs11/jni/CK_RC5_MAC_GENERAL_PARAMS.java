package aladdin.pkcs11.jni;

///////////////////////////////////////////////////////////////////////////////
// typedef struct CK_RC5_MAC_GENERAL_PARAMS {
//   CK_ULONG      ulWordsize;   
//   CK_ULONG      ulRounds;     
//   CK_ULONG      ulMacLength;  
// } CK_RC5_MAC_GENERAL_PARAMS;
///////////////////////////////////////////////////////////////////////////////
public class CK_RC5_MAC_GENERAL_PARAMS 
{
    // конструктор
    public CK_RC5_MAC_GENERAL_PARAMS(int wordsize, int rounds, int macLength)
    {
        this.wordsize  = wordsize;  // wordsize in bits
        this.rounds    = rounds;    // number of rounds
        this.macLength = macLength; // Length of MAC in bytes
    }
    public final int wordsize;      // wordsize in bits
    public final int rounds;        // number of rounds
    public final int macLength;     // Length of MAC in bytes
}
