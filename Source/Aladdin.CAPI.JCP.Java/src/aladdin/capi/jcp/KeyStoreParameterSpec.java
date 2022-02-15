package aladdin.capi.jcp;
import aladdin.capi.*; 
import java.security.spec.*; 
		
///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма с областью видимости
///////////////////////////////////////////////////////////////////////////////
public class KeyStoreParameterSpec implements AlgorithmParameterSpec 
{
    // область видимости и закодированные параметры
    private final SecurityStore scope; private final AlgorithmParameterSpec paramSpec;
    
	// конструктор
	public KeyStoreParameterSpec(SecurityStore scope, AlgorithmParameterSpec paramSpec)
	{  
		// сохранить переданные параметры
		this.scope = scope; this.paramSpec = paramSpec; 
    } 
	// область видимости
	public final SecurityStore getScope() { return scope; } 
    
    // параметры алгоритма
    public final AlgorithmParameterSpec paramSpec() { return paramSpec; }
}
