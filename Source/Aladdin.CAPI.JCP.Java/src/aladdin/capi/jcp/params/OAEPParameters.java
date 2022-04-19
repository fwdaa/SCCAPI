package aladdin.capi.jcp.params;
import aladdin.capi.jcp.*; 
import aladdin.capi.jcp.Provider; 
import aladdin.asn1.*;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.pkcs1.*;
import aladdin.capi.ansi.*; 
import java.io.*;
import java.security.spec.*;
import javax.crypto.spec.*; 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма дополнения OAEP
///////////////////////////////////////////////////////////////////////////////
public class OAEPParameters extends AlgorithmParametersSpi
{
    // провайдер и параметры адгоритма
    private OAEPParameterSpec paramSpec; 
    
    // конструктор
    public OAEPParameters(Provider provider, String algorithm) throws IOException
    { 
        // инициализировать переменные
        super(provider, aladdin.asn1.iso.pkcs.pkcs1.OID.RSA_OAEP); 
        
        // найти позицию разделителя 
        int index = algorithm.indexOf("/"); if (index >= 0) algorithm = algorithm.substring(index + 1); 
        
        // преобразовать имя в нижний регистр
        algorithm = algorithm.toLowerCase(); 
        
        // проверить корректность имени
        if (!algorithm.startsWith("oaep") || !algorithm.endsWith("padding")) 
        {
            // при ошибке выбросить исключение
            throw new UnsupportedOperationException(); 
        }
        // удалить префикс и суффикс
        algorithm = algorithm.substring(4, algorithm.length() - 7); 
        
        // проверить наличие подробного имени
        if (algorithm.length() == 0) { paramSpec = null; return; }
        
        // найти позицию разделителя
        index = algorithm.indexOf("and"); if (index < 0) throw new UnsupportedOperationException();
        
        // извлечь имя алгоритма хэширования 
        String hashName = algorithm.substring(0, index); 
        
        // извлечь имя алгоритма маскирования
        String maskName = algorithm.substring(index + 3); 
        
        // проверить поддержку алгоритма
        if (!maskName.equals("mgf1")) throw new UnsupportedOperationException(); 
        try { 
            // указать параметры алгоритма маскирования
            AlgorithmParameterSpec maskSpec = new MGF1ParameterSpec(hashName); 
            
            // инициализировать параметры алгоритма
            engineInit(new OAEPParameterSpec(
                hashName, maskName, maskSpec, PSource.PSpecified.DEFAULT
            )); 
        }
        // обработать возможное исключение
        catch (InvalidParameterSpecException e) { throw new IOException(e); }
    } 
	@Override
	protected final void engineInit(AlgorithmParameterSpec paramSpec) 
		throws InvalidParameterSpecException 
    {
        // проверить необходимость действий
        if (this.paramSpec != null && paramSpec == null) return; 
        
        // проверить тип параметров
        if (!(paramSpec instanceof OAEPParameterSpec)) throw new InvalidParameterSpecException(); 
        
        // сохранить параметры алгоритма
        engineInit((OAEPParameterSpec)paramSpec); 
	}
	private void engineInit(OAEPParameterSpec paramSpec) throws InvalidParameterSpecException 
    {
        this.paramSpec = paramSpec; 
        
        // определить идентификатор алгоритма хэширования
        String hashOID = Aliases.convertAlgorithmName(paramSpec.getMGFAlgorithm()); 
        
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(
            new ObjectIdentifier(hashOID), Null.INSTANCE
        ); 
        // определить идентификатор алгоритма маскирования
        String maskOID = Aliases.convertAlgorithmName(paramSpec.getMGFAlgorithm()); 
            
        // указать параметры алгоритма маскирования
        AlgorithmParameters mgf1Parameters = getProvider().createParameters(
            maskOID, paramSpec.getMGFParameters()
        ); 
        try { 
            // закодировать параметры алгоритма маскирования
            AlgorithmIdentifier maskAlgorithm = new AlgorithmIdentifier(
                new ObjectIdentifier(maskOID), Encodable.decode(mgf1Parameters.getEncoded())
            ); 
            // извлечь метку
            OctetString label = new OctetString(
                ((PSource.PSpecified)paramSpec.getPSource()).getValue()
            ); 
            // закодировать метку
            AlgorithmIdentifier pSourceAlgorithm = new AlgorithmIdentifier(
                new ObjectIdentifier(OID.RSA_SPECIFIED), label
            ); 
                // закодировать параметры
            IEncodable encodable = new RSAESOAEPParams(
                hashAlgorithm, maskAlgorithm, pSourceAlgorithm
            ); 
            // сохранить закодированное представление
            engineInit(encodable.encoded());
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
        
        // тип параметров не поддерживается
        throw new InvalidParameterSpecException(); 
    }
}
