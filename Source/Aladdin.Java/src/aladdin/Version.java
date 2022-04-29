package aladdin;
import java.io.*; 
import java.util.*; 

///////////////////////////////////////////////////////////////////////////////
// Номер версии
///////////////////////////////////////////////////////////////////////////////
public final class Version implements Serializable, Cloneable, Comparable<Version>
{
    private static final long serialVersionUID = 1079842078518285394L;
    
    // компоненты номера версии
    private int major;    // старший номер версии
    private int minor;    // младший номер версии
    private int build;    // старший номер сборки
    private int revision; // младший номер сборки
    
    // раскодировать номер версии
    public static Version parse(String input)
    {
        // проверить указание строки 
        if (input == null) throw new NullPointerException();
        
        // создать пустой список компонентов
        List<String> strList = new ArrayList<String>();
        
        // указать разделитель компонентов
        StringTokenizer tokenizer = new StringTokenizer(input, ".");

        // разбить строку на компоненты
        while (tokenizer.hasMoreTokens()) strList.add(tokenizer.nextToken());
              
        // проверить число компонентов
        if (strList.size() < 2 || strList.size() > 4) throw new IllegalArgumentException(); 
        
        // раскодировать старший номер версии 
        int major = Integer.parseInt(strList.get(0)); 
        
        // проверить корректность номера 
        if (major < 0) throw new IllegalArgumentException();
        
        // раскодировать младший номер версии 
        int minor = Integer.parseInt(strList.get(1)); 
        
        // проверить корректность номера 
        if (minor < 0) throw new IllegalArgumentException();
        
        // проверить наличие дополнительных компонентов
        if (strList.size() == 2) return new Version(major, minor); 
        
        // раскодировать старший номер сборки
        int build = Integer.parseInt(strList.get(2)); 
        
        // проверить корректность номера 
        if (build < 0) throw new IllegalArgumentException();
        
        // проверить наличие дополнительных компонентов
        if (strList.size() == 3) return new Version(major, minor, build); 
        
        // раскодировать младший номер сборки
        int revision = Integer.parseInt(strList.get(3)); 
        
        // проверить корректность номера 
        if (revision < 0) throw new IllegalArgumentException();
        
        // вернуть общий номер версии
        return new Version(major, minor, build, revision); 
    }
    // конструктор
    public Version(String version)
    {
        // прочитать номер версии
        Version version1 = Version.parse(version);
      
        // сохранить номер версии 
        this.major = version1.major; this.minor = version1.minor;
      
        // сохранить номер сборки
        this.build = version1.build; this.revision = version1.revision;
    }
    // конструктор
    public Version(int major, int minor, int build, int revision)
    {
        // проверить корректность параметров
        if (major    < 0) throw new IllegalArgumentException();
        if (minor    < 0) throw new IllegalArgumentException();
        if (build    < 0) throw new IllegalArgumentException();
        if (revision < 0) throw new IllegalArgumentException();
        
        // сохранить номер версии 
        this.major = major; this.minor = minor;
        
        // сохранить номер сборки
        this.build = build; this.revision = revision;
    }
    // конструктор
    public Version(int major, int minor, int build)
    {
        // проверить корректность параметров
        if (major < 0) throw new IllegalArgumentException();
        if (minor < 0) throw new IllegalArgumentException();
        if (build < 0) throw new IllegalArgumentException();
        
        // сохранить номер версии 
        this.major = major; this.minor = minor;
        
        // сохранить номер сборки
        this.build = build; this.revision = -1; 
    }
    // конструктор
    public Version(int major, int minor)
    {
        // проверить корректность параметров
        if (major < 0) throw new IllegalArgumentException();
        if (minor < 0) throw new IllegalArgumentException();
        
        // сохранить номер версии 
        this.major = major; this.minor = minor;

        // инициализировать номер сборки
        this.build = -1; this.revision = -1; 
    }
    // конструктор
    public Version() { this.major = 0; this.minor = 0; 
    
        // инициализировать номер версии и номер сборки
        this.build = -1; this.revision = -1;
    }
    // компоненты номера версии
    public final int major   () { return major;    }
    public final int minor   () { return minor;    } 
    public final int build   () { return build;    } 
    public final int revision() { return revision; } 
    
    // создать копию версии
    public Object сlone() { Version version = new Version(major, minor); 
    
        // создать копию версии
        version.build = build; version.revision = revision; return version;  
    }
    // сравнить номера версий
    @Override public int compareTo(Version value)
    {
        // проверить указание версии 
        if (value == null) return 1;
      
        // сравнить компоненты номера версии
        if (major    != value.major   ) return (major    > value.major   ) ? 1 : -1;
        if (minor    != value.minor   ) return (minor    > value.minor   ) ? 1 : -1;
        if (build    != value.build   ) return (build    > value.build   ) ? 1 : -1;
        if (revision != value.revision) return (revision > value.revision) ? 1 : -1;
        
        return 0;
    }
    // сравнить объекты 
    @Override public boolean equals(Object obj)
    {
        // проверить наличие объекта
        if (this == obj) return true; if (obj == null) return false; 
        
        // проверить тип объекта
        if (!(obj instanceof Version)) return false; 
        
        // сравнить объекты
        return equals((Version)obj); 
    }
    public final boolean equals(Version obj)
    {
        // проверить наличие объекта
        if (this == obj) return true; if (obj == null) return false; 
        
        // сравнить номер версии
        return major == obj.major && minor    == obj.minor    && 
               build == obj.build && revision == obj.revision;
    }
    // хэш-код версии
    @Override public int hashCode()
    {
        // получить хэш-код версии
        return ((major & 0x0F) << 28) | ((minor    & 0x0FF) << 20) | 
               ((build & 0xFF) << 12) | ((revision & 0xFFF) <<  0);
    }
    // получить строковое представление 
    @Override public String toString()
    {
        // проверить число компонентов
        if (build    == -1) return toString(2);
        if (revision == -1) return toString(3);
      
        // получить строковое представление 
        return toString(4);
    }
    // получить строковое представление 
    public String toString(int fieldCount)
    {
        // проверить наличие полей 
        if (fieldCount == 0) return new String(); 
        
        // вернуть старший номер версии 
        if (fieldCount == 1) return Integer.toString(major); 
        if (fieldCount == 2)
        {
            // вернуть номер версии 
            return String.format("%1$d.%2$d", major, minor); 
        }
        // проверить наличие версии сборки
        if (build == -1) throw new IllegalArgumentException(); 
        if (fieldCount == 3)
        {
            // вернуть номер версии 
            return String.format("%1$d.%2$d.%3$d", major, minor, build); 
        }
        // проверить наличие младшего номера версии сборки
        if (revision  == -1) throw new IllegalArgumentException(); 
        if (fieldCount == 4)
        {
            // вернуть номер версии 
            return String.format("%1$d.%2$d.%3$d.%4$d", major, minor, build, revision); 
        }
        // при ошибке выбросить исключение 
        throw new IllegalArgumentException(); 
    }
}
