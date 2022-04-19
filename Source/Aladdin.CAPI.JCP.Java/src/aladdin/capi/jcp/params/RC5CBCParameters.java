package aladdin.capi.jcp.params;
import aladdin.capi.jcp.*; 
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.ansi.rsa.*;
import java.security.spec.*;
import java.io.*; 
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма RC5 (режим CBC)
///////////////////////////////////////////////////////////////////////////////
public class RC5CBCParameters extends AlgorithmParametersSpi
{
    // параметры алгоритма
    private RC5ParameterSpec paramSpec;
    
    // конструктор
    public RC5CBCParameters(Provider provider, String algorithm) 
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
        this.paramSpec = (RC5ParameterSpec)paramSpec; 
        
        // проверить наличие синхропосылки
        if (this.paramSpec.getIV() == null) throw new InvalidParameterSpecException(); 
        
        // закодировать параметры
        IEncodable encodable = new RC5CBCParameter(
            new Integer    (this.paramSpec.getVersion ()), 
            new Integer    (this.paramSpec.getRounds  ()), 
            new Integer    (this.paramSpec.getWordSize()), 
            new OctetString(this.paramSpec.getIV      ())
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
            // вернуть синхропосылку
            return (T)new IvParameterSpec(paramSpec.getIV()); 
        }
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
}
