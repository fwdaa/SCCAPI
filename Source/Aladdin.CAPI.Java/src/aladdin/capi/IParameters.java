package aladdin.capi;
import java.io.*;
import java.security.spec.*;

///////////////////////////////////////////////////////////////////////////
// Параметры алгоритма
///////////////////////////////////////////////////////////////////////////
public interface IParameters extends AlgorithmParameterSpec, Serializable  
{
    // получить параметры алгоритма
    <T extends AlgorithmParameterSpec> T getParameterSpec(Class<T> specType)
        throws InvalidParameterSpecException;
}
