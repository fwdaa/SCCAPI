package aladdin.capi;
import aladdin.io.*;
import java.util.*;
import java.io.*;

///////////////////////////////////////////////////////////////////////////
// Информация об защищенном объекте
///////////////////////////////////////////////////////////////////////////
public final class SecurityInfo
{
    // имя хранилища защищенных объектов и имя объекта
    public final Scope scope; public final String store; public final Object name;
    
    // конструктор
    public SecurityInfo(Scope scope, String store, Object name)
    {
	// сохранить переданные параметры
	this.scope = scope; this.store = store; this.name = name; 
    }
    // полное имя контейнера
    public String fullName()  
    { 
        // проверить наличие родительского хранилища
        if (store == null) return name.toString(); 
                
        // указать отображаемое имя объекта
        String displayName = "<NONAME>"; if (name instanceof MemoryStream)
        {
            // выполнить преобразование типа
            MemoryStream stream = (MemoryStream)name;

            // закодировать содержимое буфера
            displayName = Base64.getEncoder().encodeToString(stream.toArray());
        }
        // указать отображаемое имя объекта
        else if (name instanceof String) displayName = name.toString(); 
        
        // вернуть полное имя объекта
        return String.format("%1$s%2$s%3$s", store, File.separator, displayName); 
    }
    // сравнить объекты
    @Override
    public boolean equals(Object obj) 
    { 
        // проверить тип оръекта
        if (!(obj instanceof SecurityInfo)) return false;
        
        // сравнить объекты
        return equals((SecurityInfo)obj); 
    }
    // сравнить объекты
    public boolean equals(SecurityInfo obj)
    {
        // проверить наличие объекта
        if (obj == null) return false; if (obj == this) return true; 

        // сравнить имена объектов
        return (name instanceof String) && fullName().equals(obj.fullName()); 
    }
    // хэш-код объекта
    @Override
    public int hashCode() { return fullName().hashCode(); }
}; 
