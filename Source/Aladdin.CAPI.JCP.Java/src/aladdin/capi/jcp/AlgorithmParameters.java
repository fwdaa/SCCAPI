package aladdin.capi.jcp;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма 
///////////////////////////////////////////////////////////////////////////////
public final class AlgorithmParameters extends java.security.AlgorithmParameters
{
    // конструктор
    public AlgorithmParameters(Provider provider, AlgorithmParametersSpi spi)
    {
        // сохранить переданные параметры
        super(spi, provider, spi.getAlgorithm());
    }
}
