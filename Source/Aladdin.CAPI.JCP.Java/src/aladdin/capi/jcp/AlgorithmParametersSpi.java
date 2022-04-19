package aladdin.capi.jcp;
import aladdin.asn1.*; 
import java.io.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма
///////////////////////////////////////////////////////////////////////////////
public class AlgorithmParametersSpi extends java.security.AlgorithmParametersSpi
{
    // провайдер, имя алгоритма и закодированное представление параметров
    private final Provider provider; private final String algorithm; private IEncodable encodable;
    
    // конструктор
    public AlgorithmParametersSpi(Provider provider, String algorithm) 
    { 
        // сохранить переданные параметры
        this.provider = provider; this.algorithm = algorithm; this.encodable = null;
    } 
    @Override protected void engineInit(AlgorithmParameterSpec paramSpec) 
        throws InvalidParameterSpecException 
    {
        // операция не поддерживается
        throw new InvalidParameterSpecException(); 
    }
    // конструктор
	@Override protected final void engineInit(byte[] encoded) throws IOException 
	{
        // раскодировать параметры
        engineInit(encoded, "ASN.1"); 
	}
    // конструктор
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
    // используемый провайдер
    public final Provider getProvider() { return provider; }
    // идентификатор ключа или алгоритма
    public final String getAlgorithm() { return algorithm; }
    // закодированное представление параметров
    public final IEncodable getEncodable() { return encodable; }
    
    // получить параметры алгоритма
    @Override protected <T extends AlgorithmParameterSpec> 
        T engineGetParameterSpec(Class<T> paramSpec) 
            throws InvalidParameterSpecException 
    {
        // операция не поддерживается
        throw new InvalidParameterSpecException(); 
    }
    // получить закодированное представление
	@Override protected final byte[] engineGetEncoded()  
	{
		// получить закодированное представление
		return engineGetEncoded("ASN.1"); 
	}
    // получить закодированное представление
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
