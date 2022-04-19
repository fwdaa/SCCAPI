package aladdin.capi.jcp.params;
import aladdin.capi.jcp.*; 
import aladdin.capi.jcp.Provider; 
import aladdin.asn1.*;
import aladdin.asn1.Integer;
import aladdin.asn1.iso.*;
import aladdin.asn1.iso.pkcs.pkcs1.*;
import aladdin.capi.ansi.*; 
import java.io.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма дополнения PSS
///////////////////////////////////////////////////////////////////////////////
public class PSSParameters extends AlgorithmParametersSpi
{
    // параметры адгоритма
    private PSSParameterSpec paramSpec; 
    
    // конструктор
    public PSSParameters(Provider provider, String oid) 
    {
        // инициализировать переменные
        super(provider, oid); paramSpec = null; 
    }
	@Override
	protected void engineInit(AlgorithmParameterSpec paramSpec) 
		throws InvalidParameterSpecException 
    {
        // проверить тип параметров
        if (!(paramSpec instanceof PSSParameterSpec)) throw new InvalidParameterSpecException(); 
        
        // сохранить параметры алгоритма
        this.paramSpec = (PSSParameterSpec)paramSpec; 
            
        // проверить значение завершителя
        if (this.paramSpec.getTrailerField() != 0xBC) throw new InvalidParameterSpecException(); 
        
        // определить идентификатор алгоритма хэширования
        String hashOID = Aliases.convertAlgorithmName(this.paramSpec.getDigestAlgorithm()); 
        
        // закодировать параметры алгоритма хэширования
        AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(
            new ObjectIdentifier(hashOID), Null.INSTANCE
        ); 
        // определить идентификатор алгоритма маскирования
        String maskOID = Aliases.convertAlgorithmName(this.paramSpec.getMGFAlgorithm()); 

        // указать параметры алгоритма маскирования
        AlgorithmParameters mgf1Parameters = getProvider().createParameters(
            maskOID, this.paramSpec.getMGFParameters()
        ); 
        try { 
            // закодировать параметры алгоритма маскирования
            AlgorithmIdentifier maskAlgorithm = new AlgorithmIdentifier(
                new ObjectIdentifier(maskOID), Encodable.decode(mgf1Parameters.getEncoded())
            ); 
            // закодировать параметры
            IEncodable encodable = new RSASSAPSSParams(hashAlgorithm, maskAlgorithm, 
                new Integer(this.paramSpec.getSaltLength()), new Integer(1)
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
