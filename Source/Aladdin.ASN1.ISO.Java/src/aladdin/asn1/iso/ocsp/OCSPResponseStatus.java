package aladdin.asn1.iso.ocsp;

// OCSPResponseStatus ::= ENUMERATED {
//    successful          (0),  
//    malformedRequest    (1),  
//    internalError       (2),  
//    tryLater            (3),  
//    sigRequired         (5),  
//    unauthorized        (6)   
// }

public final class OCSPResponseStatus 
{
	public static final int SUCCESSFUL          =  0; 
	public static final int MALFORMED_REQUEST	=  1;
	public static final int INTERNAL_ERROR		=  2;
	public static final int TRY_LATER           =  3;
	public static final int SIG_REQUIRED		=  5;
	public static final int UNATHORIZED         =  6;
}
