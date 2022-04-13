package aladdin.capi.ansi.params;
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.capi.*; 
import aladdin.capi.ansi.*; 
import java.io.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма маскирования MGF1
///////////////////////////////////////////////////////////////////////////////
public class MGF1Parameters implements IEncodedParameters
{
    // конструктор
    public MGF1Parameters(MGF1ParameterSpec paramSpec)
     
        // вызвать метод и сохранить переданные параметры 
        { this.paramSpec = paramSpec; } private final MGF1ParameterSpec paramSpec; 
    
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
        
        // закодировать параметры
        return new AlgorithmIdentifier(new ObjectIdentifier(hashOID), Null.INSTANCE); 
    }
}
