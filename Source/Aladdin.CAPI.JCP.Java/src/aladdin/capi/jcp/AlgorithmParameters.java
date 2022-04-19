package aladdin.capi.jcp;
import aladdin.asn1.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма 
///////////////////////////////////////////////////////////////////////////////
public final class AlgorithmParameters extends java.security.AlgorithmParameters
{
    // закодированное представление параметров
    public static IEncodable encode(java.security.AlgorithmParameters parameters) throws IOException 
    { 
        // получить закодированное представление параметров
        byte[] encoded = parameters.getEncoded("ASN.1"); 
        
        // вернуть закодированное представление параметров
        return (encoded != null) ? Encodable.decode(encoded) : null; 
    }
    // реализация параметров алгоритма
    private final AlgorithmParametersSpi spi; 
    
    // конструктор
    public AlgorithmParameters(AlgorithmParametersSpi spi)
    {
        // сохранить переданные параметры
        super(spi, spi.getProvider(), spi.getAlgorithm()); this.spi = spi; 
    }
    // закодированное представление параметров
    public final IEncodable getEncodable() { return spi.getEncodable(); }
}
