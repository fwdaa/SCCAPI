package aladdin.capi.jcp.params;
import aladdin.capi.jcp.*; 
import aladdin.asn1.*;
import aladdin.asn1.ansi.rsa.*;
import java.security.spec.*;
import java.io.*; 
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма RC2
///////////////////////////////////////////////////////////////////////////////
public class RC2Parameters extends AlgorithmParametersSpi
{
    // параметры алгоритма
    private RC2ParameterSpec paramSpec;
    
    // конструктор
    public RC2Parameters(Provider provider, String algorithm) 
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
        
        // проверить отсутствие синхропосылки
        if (this.paramSpec.getIV() != null) throw new InvalidParameterSpecException(); 
            
        // закодировать число эффективных битов
        IEncodable encodable = RC2ParameterVersion.getVersion(
            this.paramSpec.getEffectiveKeyBits()
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
        
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
}
