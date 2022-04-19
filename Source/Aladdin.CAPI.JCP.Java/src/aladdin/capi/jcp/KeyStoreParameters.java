package aladdin.capi.jcp;
import aladdin.asn1.*;
import java.io.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма с областью видимости
///////////////////////////////////////////////////////////////////////////////
public class KeyStoreParameters extends AlgorithmParametersSpi
{
    // параметры алгоритма с областью видимости
    private KeyStoreParameterSpec paramSpec; 
    
    // конструктор
    public KeyStoreParameters(Provider provider, String algorithm) 
    { 
        // инициализировать переменные
        super(provider, algorithm); paramSpec = null;
    } 
	@Override
	protected void engineInit(AlgorithmParameterSpec paramSpec) 
		throws InvalidParameterSpecException 
    {
        // в зависимости от типа параметров
        if (paramSpec instanceof KeyStoreParameterSpec) 
        {
            // выполнить преобразование типа
            this.paramSpec = (KeyStoreParameterSpec)paramSpec; 
        }
        // в зависимости от типа параметров
        else if (paramSpec == null)
        {
            // сохранить параметры
            this.paramSpec = new KeyStoreParameterSpec(null, null); 
        }
        // при ошибке выбросить исключение
        else throw new InvalidParameterSpecException(); 
        
        // получить параметры алгоритма шифрования
        java.security.AlgorithmParameters parameters = this.paramSpec.parameters(); 
        try { 
            // указать закодированное представление по умолчанию
            byte[] encoded = Null.INSTANCE.encoded(); 
        
            // указать закодированное представление
            if (parameters != null) encoded = parameters.getEncoded("ASN.1"); 
        
            // сохранить закодированное представление
            engineInit(encoded); 
        }
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
        
        // получить параметры алгоритма шифрования
        java.security.AlgorithmParameters parameters = paramSpec.parameters(); 
        
        // проверить наличие параметров 
        if (parameters == null) throw new InvalidParameterSpecException(); 
        
        // извлчеь параметры
        return parameters.getParameterSpec(specType); 
    }
}
