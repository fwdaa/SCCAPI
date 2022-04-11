package aladdin.capi.environment;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры приложения
///////////////////////////////////////////////////////////////////////////
public class ConfigSection implements Serializable 
{
    private static final long serialVersionUID = -8927604509474079208L;
    
	// фабрики алгоритмов и генераторы случайных данных
    private final ConfigFactory[] factories; private final ConfigRandFactory[] rands; 
	// расширения криптографических культур
    private final ConfigKey[] keys; private final ConfigPlugin[] plugins; 

    // конструктор
    public ConfigSection(ConfigFactory[] factories, ConfigRandFactory[] rands, 
        ConfigKey[] keys, ConfigPlugin[] plugins)
    {
        // сохранить переданные параметры
        this.factories = factories; this.rands = rands; 

        // сохранить переданные параметры
        this.keys = keys; this.plugins = plugins; 
    }
	// фабрики алгоритмов
	public final ConfigFactory[] factories() { return factories; }
	// генераторы случайных данных
	public final ConfigRandFactory[] rands() { return rands; }
	// используемые ключи
	public final ConfigKey[] keys() { return keys; }
	// расширения криптографических культур
	public final ConfigPlugin[] plugins() { return plugins; }
}
