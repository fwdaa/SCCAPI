package aladdin.capi.jcp;
import aladdin.capi.*; 
import aladdin.asn1.*; 
import java.security.*;
import java.security.spec.*;
import java.io.*;
import javax.crypto.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма
///////////////////////////////////////////////////////////////////////////////
public final class AlgorithmParametersSpi extends java.security.AlgorithmParametersSpi
{
    // фабрика алгоритмов и область видимости
    private final Factory factory; private SecurityStore scope; 
    // закодированное представление параметров
    private final String algorithm; private IEncodable encodable; private byte[] iv; 
    
    // конструктор
    public static AlgorithmParametersSpi getInstance(Provider provider,
        String algorithm, java.security.AlgorithmParameters parameters) 
            throws InvalidAlgorithmParameterException
    {
        try { 
            // проверить указание параметров алгоритма
            if (parameters == null) return provider.createParameters(algorithm, null); 
            
            // в зависимости от типа параметров
            if (parameters instanceof AlgorithmParameters)
            {
                // вернуть реализацию параметров алгоритма
                return ((AlgorithmParameters)parameters).spi(); 
            }
            // создать параметры алгоритма
            return new AlgorithmParametersSpi(provider, parameters); 
        }
        // обработать возможное исключение
        catch (InvalidParameterSpecException e) 
        { 
            // изменить тип исключения 
            throw new InvalidAlgorithmParameterException(e.getMessage()); 
        }
    }
    // конструктор
    private AlgorithmParametersSpi(Provider provider, 
        java.security.AlgorithmParameters parameters) throws InvalidAlgorithmParameterException
    {
        // сохранить переданные параметры
        this(provider, parameters.getAlgorithm()); encodable = null;
        
        // инициализировать параметры
        try { engineInit(parameters.getEncoded("ASN1.1")); } 
        
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidAlgorithmParameterException(e.getMessage()); }
        try { 
            // сохранить синхропосылку при ее наличии
            iv = parameters.getParameterSpec(IvParameterSpec.class).getIV(); 
        }
        // обработать возможное исключение
        catch (InvalidParameterSpecException e) {}
    }
    // конструктор
    public AlgorithmParametersSpi(Provider provider, String algorithm) 
    { 
        // сохранить переданные параметры
        this.factory = provider.factory(); this.scope = null; 
        
        // сохранить переданные параметры
        this.algorithm = algorithm; this.encodable = null;
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
        // проверить указание параметров
        if (paramSpec == null) { encodable = null; iv = null; return; } 
        try { 
            // в зависимости от типа параметров
            if (paramSpec instanceof EncodedParameterSpec)
            {
                // выполнить преобразование типа
                EncodedParameterSpec encodedParameterSpec = (EncodedParameterSpec)paramSpec; 

                // инициализировать параметры
                engineInit(encodedParameterSpec.getEncoded(), encodedParameterSpec.getFormat()); 
                
                // сохранить синхропосылку
                iv = encodedParameterSpec.getIV(); 
            }
            // в зависимости от типа параметров
            else if (paramSpec instanceof IvParameterSpec)
            {
                // сохранить синхропосылку
                iv = ((IvParameterSpec)paramSpec).getIV(); 
            }
            else {
                // найти фабрику кодирования 
                aladdin.capi.KeyFactory keyFactory = factory.getKeyFactory(algorithm); 

                // при указании параметров ключа
                if (keyFactory == null) throw new InvalidParameterSpecException();

                // создать параметры алгоритма
                IParameters parameters = keyFactory.createParameters(paramSpec); 

                // получить закодированное представление
                encodable = (parameters != null) ? keyFactory.encodeParameters(parameters) : null; 
            }
        }
        // обработать возможное исключение
        catch (IOException e) { throw new InvalidParameterSpecException(e.getMessage()); }
	}
	@Override protected final void engineInit(byte[] encoded) throws IOException 
	{
        // раскодировать параметры
        engineInit(encoded, "ASN.1"); 
	}
	@Override protected void engineInit(byte[] encoded, String format) throws IOException 
	{
        // проверить наличие параметров
        if (encoded == null) { encodable = null; return; }
        
        // при указании формата
        if (format != null && format.length() != 0)
        {
            // проверить поддержку формата
            if (!format.equals("ASN.1")) throw new IOException(); 
        }
        // раскодировать параметры
        encodable = Encodable.decode(encoded); 
	}
    // область видимости
    public final SecurityStore getScope() { return scope; }
    // идентификатор ключа или алгоритма
    public final String getAlgorithm() { return algorithm; }
    // закодированное представление параметров
    public final IEncodable getEncodable() { return encodable; }
    
	@Override
    @SuppressWarnings({"unchecked"}) 
	protected <T extends AlgorithmParameterSpec>
		T engineGetParameterSpec(Class<T> specType) throws InvalidParameterSpecException 
	{
        // при запросе закодированного представления
        if (specType.isAssignableFrom(EncodedParameterSpec.class))
        {
            // получить закодированное представление
            byte[] encoded = (encodable != null) ? encodable.encoded() : null; 
            
            // вернуть закодированное представление
            return (T)new EncodedParameterSpec(encoded, iv); 
        }
        // при запросе синхропосылки
        else if (specType.isAssignableFrom(IvParameterSpec.class))
        {
            // проверить наличие синхропосылки
            if (iv == null) throw new InvalidParameterSpecException(); 
            
            // вернуть синхропосылку
            return (T)new IvParameterSpec(iv); 
        }
        else {
            // найти фабрику кодирования 
            aladdin.capi.KeyFactory keyFactory = factory.getKeyFactory(algorithm); 
           
            // проверить наличие фабрики
            if (keyFactory == null) throw new InvalidParameterSpecException();
            try { 
                // раскодировать параметры
                IParameters parameters = keyFactory.decodeParameters(encodable); 

                // извлечь параметры алгоритма
                return (T)keyFactory.getParametersSpec(parameters, specType); 
            }
            // обработать возможное исключение
            catch (IOException e) { throw new InvalidParameterSpecException(e.getMessage()); }
        }
	}
	@Override protected final byte[] engineGetEncoded()  
	{
		// получить закодированное представление
		return engineGetEncoded("ASN.1"); 
	}
	@Override protected byte[] engineGetEncoded(String format) 
	{
        // при указании формата
        if (format != null && format.length() != 0)
        {
            // проверить поддержку формата
            if (!format.equals("ASN.1")) throw new UnsupportedOperationException(); 
        }
        // вернуть закодированное представление
        return (encodable != null) ? encodable.encoded() : null; 
	}
    // вернуть идентификатор параметров
	@Override protected String engineToString() { return algorithm; }
}
