package aladdin.capi.jcp.params;
import aladdin.capi.jcp.*; 
import aladdin.capi.jcp.Provider; 
import aladdin.asn1.*;
import aladdin.capi.*;
import java.io.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры ключа
///////////////////////////////////////////////////////////////////////////////
public class KeyParameters extends AlgorithmParametersSpi
{
    // фабрика кодирования ключей
    private final aladdin.capi.KeyFactory keyFactory; private IParameters parameters;
    
    // конструктор
    public KeyParameters(Provider provider, String keyOID) 
    { 
        // инициализировать переменные
        super(provider, keyOID); parameters = null; 
        
        // получить фабрику кодирования ключей
        keyFactory = provider.factory().getKeyFactory(keyOID); 
        
        // проверить наличие фабрики
        if (keyFactory == null) throw new UnsupportedOperationException(); 
    } 
	@Override
	protected void engineInit(AlgorithmParameterSpec paramSpec) 
		throws InvalidParameterSpecException 
    {
        // инициализировать параметры
        parameters = keyFactory.createParameters(paramSpec); IEncodable encodable = null; 
        try { 
            // закодировать параметры
            encodable = keyFactory.encodeParameters(parameters); 
        }
        // обработать возможное исключение
        catch (UnsupportedOperationException e) { return; }
        
        // сохранить закодированное представление
        try { engineInit(encodable.encoded()); }
        
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidParameterSpecException(e.getMessage()); }
	}
    // извлечь параметры
    @Override protected <T extends AlgorithmParameterSpec> 
        T engineGetParameterSpec(Class<T> specType) 
            throws InvalidParameterSpecException 
    {
        // извлечь параметры
        return parameters.getParameterSpec(specType); 
    }
}
