package aladdin.capi.ansi.culture; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import aladdin.asn1.iso.pkcs.pkcs1.*;
import aladdin.capi.*; 

///////////////////////////////////////////////////////////////////////////
// Национальные особенности RSA OAEP/PSS
///////////////////////////////////////////////////////////////////////////
public class RSAOP extends RSA
{
    @Override public AlgorithmIdentifier ciphermentAlgorithm(IRand rand) 
    { 
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP), 
            new RSAESOAEPParams(null, null, null)
        ); 
    }
    @Override public AlgorithmIdentifier signHashAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS), 
            new RSASSAPSSParams(null, null, null, null)
        ); 
    }
    @Override public AlgorithmIdentifier signDataAlgorithm(IRand rand) 
    {
        // вернуть параметры алгоритма
        return new AlgorithmIdentifier(
            new ObjectIdentifier(aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_PSS), 
            new RSASSAPSSParams(null, null, null, null)
        ); 
    }
}
