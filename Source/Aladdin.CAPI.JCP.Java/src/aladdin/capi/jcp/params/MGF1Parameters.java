package aladdin.capi.jcp.params;
import aladdin.capi.jcp.*; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.capi.ansi.*; 
import java.io.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма маскирования MGF1
///////////////////////////////////////////////////////////////////////////////
public class MGF1Parameters extends AlgorithmParametersSpi
{
    // параметры алгоритма
    private MGF1ParameterSpec paramSpec;
    
    // конструктор
    public MGF1Parameters(Provider provider, String oid) 
    { 
        // инициализировать переменные
        super(provider, oid); paramSpec = null; 
    } 
	@Override
	protected void engineInit(AlgorithmParameterSpec paramSpec) 
		throws InvalidParameterSpecException 
    {
        // проверить тип параметров
        if (!(paramSpec instanceof MGF1ParameterSpec)) throw new InvalidParameterSpecException(); 
        
        // сохранить параметры алгоритма
        this.paramSpec = (MGF1ParameterSpec)paramSpec; 
            
        // определить идентификатор алгоритма хэширования
        String hashOID = Aliases.convertAlgorithmName(this.paramSpec.getDigestAlgorithm()); 
        
        // закодировать параметры
        IEncodable encodable = new AlgorithmIdentifier(new ObjectIdentifier(hashOID), Null.INSTANCE); 
        
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
