package aladdin.capi.environment;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Параметры приложения
///////////////////////////////////////////////////////////////////////////
public class ConfigSection implements Serializable 
{
    private static final long serialVersionUID = 6863973157320566421L;
    
    private final ConfigAuthentications authentications; // параметры аутентификации 
    private final ConfigFactory     [] factories;        // фабрики алгоритмов
    private final ConfigRandFactory [] rands;            // генераторы случайных данных
    private final ConfigKey         [] keys;             // идентификаторы ключей
    private final ConfigPlugin      [] plugins;          // расширения криптографических культур

	public final ConfigAuthentications authentications() { return authentications;  }
	public final ConfigFactory      [] factories      () { return factories;        }
	public final ConfigRandFactory  [] rands          () { return rands;            }
	public final ConfigKey          [] keys           () { return keys;             }
	public final ConfigPlugin       [] plugins        () { return plugins;          }
    
    // конструктор
    public ConfigSection(ConfigAuthentications authentications, 
        ConfigFactory[] factories, ConfigRandFactory[] rands, 
        ConfigKey[] keys, ConfigPlugin[] plugins)
    {
        // сохранить переданные параметры
        this.authentications = authentications; 
        
        // сохранить переданные параметры
        this.factories = factories; this.rands = rands; 

        // сохранить переданные параметры
        this.keys = keys; this.plugins = plugins; 
    }
}
