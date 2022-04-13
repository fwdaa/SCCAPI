package aladdin.capi.ansi.params;
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.ansi.rsa.*;
import aladdin.capi.*; 
import java.security.spec.*;
import java.io.*; 
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма RC2
///////////////////////////////////////////////////////////////////////////////
public class RC2Parameters implements IEncodedParameters
{
    // конструктор
    public RC2Parameters(RC2ParameterSpec paramSpec)
    
        // сохранить переданные параметры 
        { this.paramSpec = paramSpec; } private final RC2ParameterSpec paramSpec; 
        
    // извлечь параметры
    @SuppressWarnings({"unchecked"}) 
    @Override public <T extends AlgorithmParameterSpec> 
        T getParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException
    { 
        // вернуть параметры
        if (specType.isAssignableFrom(paramSpec.getClass())) return (T)paramSpec; 
        
        // при запросе синхропосылки
        if (specType.isAssignableFrom(IvParameterSpec.class))
        {
            // проверить наличие синхропосылки
            if (paramSpec.getIV() == null) throw new InvalidParameterSpecException(); 
            
            // вернуть синхропосылку
            return (T)new IvParameterSpec(paramSpec.getIV()); 
        }
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    } 
    @Override
    public IEncodable encode() throws IOException
    {
        // проверить наличие синхропосылки
        if (paramSpec.getIV() == null) throw new IOException(); 

        // закодировать число эффективных битов
        Integer version = RC2ParameterVersion.getVersion(
            paramSpec.getEffectiveKeyBits()
        ); 
        // закодировать параметры
        return new RC2CBCParams(version, new OctetString(paramSpec.getIV())); 
    }
}
