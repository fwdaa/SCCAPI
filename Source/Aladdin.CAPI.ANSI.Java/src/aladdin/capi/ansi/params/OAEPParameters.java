package aladdin.capi.ansi.params;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.pkcs1.*;
import aladdin.capi.*; 
import aladdin.capi.ansi.*; 
import java.io.*;
import java.security.spec.*;
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма дополнения OAEP
///////////////////////////////////////////////////////////////////////////////
public class OAEPParameters implements IEncodedParameters
{
    // конструктор
    public OAEPParameters(OAEPParameterSpec paramSpec)
    
        // сохранить переданные параметры 
        { this.paramSpec = paramSpec; } private final OAEPParameterSpec paramSpec; 
        
    // извлечь параметры
    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    { 
        // вернуть параметры
        if (specType.isAssignableFrom(paramSpec.getClass())) return (T)paramSpec; 
        
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    } 
    @Override
    public IEncodable encode() throws IOException
    {
        // определить идентификатор алгоритма хэширования
        String hashOID = Aliases.convertAlgorithmName(paramSpec.getDigestAlgorithm()); 
        
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(
            new ObjectIdentifier(hashOID), Null.INSTANCE
        ); 
        // определить идентификатор алгоритма маскирования
        String maskOID = Aliases.convertAlgorithmName(paramSpec.getMGFAlgorithm()); 
        
        // указать параметры алгоритма маскирования
        MGF1Parameters mgf1Parameters = new MGF1Parameters(
            (MGF1ParameterSpec)paramSpec.getMGFParameters()
        ); 
        // закодировать параметры алгоритма маскирования
        AlgorithmIdentifier maskAlgorithm = new AlgorithmIdentifier(
            new ObjectIdentifier(maskOID), mgf1Parameters.encode()
        ); 
        // извлечь метку
        OctetString label = new OctetString(
            ((PSource.PSpecified)paramSpec.getPSource()).getValue()
        ); 
        // закодировать метку
        AlgorithmIdentifier pSource = new AlgorithmIdentifier(
            new ObjectIdentifier(OID.RSA_SPECIFIED), label
        ); 
        // закодировать параметры
        return new RSAESOAEPParams(hashAlgorithm, maskAlgorithm, pSource); 
    }
}
