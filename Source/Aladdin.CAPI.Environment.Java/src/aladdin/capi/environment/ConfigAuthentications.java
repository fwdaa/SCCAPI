package aladdin.capi.environment;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Элемент описания фабрики классов
///////////////////////////////////////////////////////////////////////////
public class ConfigAuthentications implements Serializable
{
    private static final long serialVersionUID = 5925701835596592786L;
    
    // число попыток аутентификации 
    private final int attempts; 
    
    // конструктор
    public ConfigAuthentications(int attempts) { this.attempts = attempts; }
    
    // число попыток аутентификации 
    public int attempts() { return attempts; }
}
