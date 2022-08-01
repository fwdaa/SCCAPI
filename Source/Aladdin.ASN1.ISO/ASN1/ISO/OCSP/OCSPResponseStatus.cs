// OCSPResponseStatus ::= ENUMERATED {
//    successful          (0),  
//    malformedRequest    (1),  
//    internalError       (2),  
//    tryLater            (3),  
//    sigRequired         (5),  
//    unauthorized        (6)   
// }

namespace Aladdin.ASN1.ISO.OCSP
{
	public enum OCSPResponseStatus
	{
        successful            = 0,
        malformedRequest      = 1,
        internalError         = 2,
        tryLater              = 3,
        sigRequired           = 5,
        unauthorized          = 6 
    }
}
