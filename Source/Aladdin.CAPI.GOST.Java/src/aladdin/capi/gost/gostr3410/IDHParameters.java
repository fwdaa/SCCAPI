package aladdin.capi.gost.gostr3410;
import aladdin.asn1.iso.*; 
import java.math.*;

///////////////////////////////////////////////////////////////////////////
// Параметры DH
///////////////////////////////////////////////////////////////////////////
public interface IDHParameters extends aladdin.capi.IParameters
{
    BigInteger getP(); // параметр P
    BigInteger getQ(); // параметр Q
    BigInteger getG(); // параметр G
    
    // параметры проверки
    AlgorithmIdentifier validationParameters();     
}
