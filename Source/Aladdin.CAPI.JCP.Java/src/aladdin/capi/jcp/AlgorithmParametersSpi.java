package aladdin.capi.jcp;
import aladdin.capi.*; 
import aladdin.asn1.*; 
import aladdin.asn1.iso.*; 
import java.security.*;
import java.security.spec.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма
///////////////////////////////////////////////////////////////////////////////
public final class AlgorithmParametersSpi extends java.security.AlgorithmParametersSpi
{
    // используемая фабрика алгоритмов
    private final Factory factory; private IParameters parameters; 
    // область видимости и закодированное представление параметров
    private SecurityStore scope; private AlgorithmIdentifier encodedParameters; 
    
    // создать параметры алгоритма   
	public static AlgorithmParametersSpi create(
        Provider provider, AlgorithmParameterSpec spec) 
		throws InvalidParameterSpecException
	{ 
		// проверить наличие параметров
		if (spec == null) throw new InvalidParameterSpecException(); 
        
        // создать экземпляр параметров
        AlgorithmParametersSpi parameters = new AlgorithmParametersSpi(
            provider.getFactory()
        );
		// раскодировать параметры
        parameters.engineInit(spec); return parameters; 
	}  
    // конструктор
    public AlgorithmParametersSpi(aladdin.capi.Factory factory, 
        java.security.AlgorithmParameters parameters) 
            throws InvalidAlgorithmParameterException 
    {
        // сохранить переданные параметры
        this.factory = factory; this.parameters = null; 
        
        // инициализировать переменные
        this.scope = null; this.encodedParameters = null;
        try { 
            // получить закодированное представление
            byte[] encoded = parameters.getEncoded(); 
            
            // проверить наличие представления
            if (encoded == null) throw new InvalidAlgorithmParameterException(); 
            
            // инициализировать параметры
            engineInit(encoded); 
        }
        // обработать возможную ошибку
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }
    }
    // конструктор
    public AlgorithmParametersSpi(aladdin.capi.Factory factory) 
    { 
        // сохранить переданные параметры
        this.factory = factory; this.parameters = null; 
        
        // инициализировать переменные
        this.scope = null; this.encodedParameters = null;
    } 
	@Override
	protected void engineInit(AlgorithmParameterSpec paramSpec) 
		throws InvalidParameterSpecException 
    {
        // в зависимости от типа параметров
        if (paramSpec instanceof KeyStoreParameterSpec)
        {
            // указать область видимости
            scope = ((KeyStoreParameterSpec)paramSpec).getScope(); 
            
            // извлечь параметры алгоритма
            paramSpec = ((KeyStoreParameterSpec)paramSpec).paramSpec();
        }
        // для всех поддерживаемых ключей
        for (aladdin.capi.KeyFactory keyFactory : factory.keyFactories())
        try {
            // создать параметры алгоритма
            parameters = keyFactory.createParameters(paramSpec); 
            
            // проверить создание параметров
            if (parameters == null) continue; 
            
            // получить закодированное представление
            IEncodable encodable = keyFactory.encodeParameters(parameters); 
            
            // сохранить закодированное представление
            encodedParameters = new AlgorithmIdentifier(
                new ObjectIdentifier(keyFactory.keyOID()), encodable
            ); 
            break; 
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidParameterSpecException(e.getMessage()); }
	}
    // область видимости
    public final SecurityStore getScope() { return scope; }
    
    // раскодированные параметры алгоритма
    public final AlgorithmIdentifier getEncodable() { return encodedParameters; }
    
	@Override
	protected final void engineInit(byte[] encoded) throws IOException 
	{
        // раскодировать параметры
        engineInit(encoded, "ASN.1"); 
	}
	@Override
	protected void engineInit(byte[] encoded, String format) throws IOException 
	{
        // проверить формат параметров
        if (format != null && format.length() != 0 && !format.equals("ASN.1"))
        {
            // при ошибке выбросить исключение
            throw new IOException(); 
        }
        // раскодировать параметры
        encodedParameters = new AlgorithmIdentifier(Encodable.decode(encoded)); 
        
        // получить идентификатор параметров
        String keyOID = encodedParameters.algorithm().value(); 
        
        // для всех поддерживаемых ключей
        for (aladdin.capi.KeyFactory keyFactory : factory.keyFactories())
        {
            // проверить совпадение идентификатора
            if (!keyFactory.keyOID().equals(keyOID)) continue; 
            
            // раскодировать параметры
            parameters = keyFactory.decodeParameters(encodedParameters.parameters()); 
        }
	}
	@Override
    @SuppressWarnings({"unchecked"}) 
	protected <T extends AlgorithmParameterSpec>
		T engineGetParameterSpec(Class<T> specType) throws InvalidParameterSpecException 
	{
        // проверить наличие инициализации
        if (encodedParameters == null) throw new IllegalStateException(); 
        
        // проверить распознавание параметров
        if (parameters == null) throw new InvalidParameterSpecException(); 
        
        // получить идентификатор параметров
        String keyOID = encodedParameters.algorithm().value(); 
        
        // для всех поддерживаемых ключей
        for (aladdin.capi.KeyFactory keyFactory : factory.keyFactories())
        {
            // проверить совпадение идентификатора
            if (!keyFactory.keyOID().equals(keyOID)) continue; 
            
            // извлечь параметры алгоритма
            return (T)keyFactory.getParametersSpec(parameters, specType); 
        }
        // при ошибке выбросить исключение
        throw new InvalidParameterSpecException(); 
	}
	@Override
	protected final byte[] engineGetEncoded()  
	{
		// получить закодированное представление
		return engineGetEncoded("ASN.1"); 
	}
	@Override
	protected byte[] engineGetEncoded(String format) 
	{
        // проверить наличие инициализации
        if (encodedParameters == null) throw new IllegalStateException(); 
        
        // проверить формат параметров
        if (format != null && format.length() != 0 && !format.equals("ASN.1"))
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
        // вернуть закодированное представление
        return encodedParameters.encoded(); 
	}
	@Override
	protected String engineToString() 
	{
        // проверить наличие инициализации
        if (encodedParameters == null) throw new IllegalStateException(); 
        
        // вернуть идентификатор параметров
        return encodedParameters.algorithm().value(); 
	}
}
