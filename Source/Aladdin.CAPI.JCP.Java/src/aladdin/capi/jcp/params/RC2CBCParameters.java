package aladdin.capi.jcp.params;
import aladdin.capi.jcp.*; 
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.ansi.rsa.*;
import java.security.spec.*;
import java.io.*; 
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма RC2 (режим CBC)
///////////////////////////////////////////////////////////////////////////////
public class RC2CBCParameters extends AlgorithmParametersSpi
{
    // параметры алгоритма
    private RC2ParameterSpec paramSpec;
    
    // конструктор
    public RC2CBCParameters(Provider provider, String algorithm) 
    { 
        // инициализировать переменные
        super(provider, algorithm); paramSpec = null; 
    } 
	@Override
	protected void engineInit(AlgorithmParameterSpec paramSpec) 
		throws InvalidParameterSpecException 
    {
        // проверить тип параметров
        if (!(paramSpec instanceof RC2ParameterSpec)) throw new InvalidParameterSpecException(); 
        
        // сохранить параметры алгоритма
        this.paramSpec = (RC2ParameterSpec)paramSpec; 
            
        // проверить наличие синхропосылки
        if (this.paramSpec.getIV() == null) throw new InvalidParameterSpecException(); 
            
        // закодировать число эффективных битов
        Integer version = RC2ParameterVersion.getVersion(
            this.paramSpec.getEffectiveKeyBits()
        ); 
        // закодировать параметры
        IEncodable encodable = new RC2CBCParams(version, 
            new OctetString(this.paramSpec.getIV())
        ); 
        // сохранить закодированное представление
        try { engineInit(encodable.encoded()); }
            
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidParameterSpecException(e.getMessage()); }
	}
    // извлечь параметры
    @SuppressWarnings({"unchecked"}) 
    @Override protected <T extends AlgorithmParameterSpec> 
        T engineGetParameterSpec(Class<T> specType) 
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
}
