package aladdin.iso7816;
import aladdin.iso7816.ber.*; 
import java.io.*;

///////////////////////////////////////////////////////////////////////////////
// Файл
///////////////////////////////////////////////////////////////////////////////
public abstract class File 
{
    // родительский каталог и шаблон описания файла
    private final DedicatedFile parent; private final FileControlInformation info;
    
    // идентификатор, путь файла и способ кодирования данных
    private final Short id; private final short[] path; private final DataCoding dataCoding;
    
    // конструктор
    protected File(Short id, DataCoding dataCoding, FileControlInformation info) throws IOException
    { 
        // сохранить переданные параметры
        this.parent = null; this.info = info;

        // указать путь файла
        this.id = id; path = (id != null) ? new short[] { id } : null; 
        
        // сохранить способ кодирования данных
        this.dataCoding = this.info.getDataCoding(dataCoding); 
    }
    // конструктор
    protected File(DedicatedFile parent, Short id, FileControlInformation info) throws IOException 
    { 
        // сохранить переданные параметры
        this.parent = parent; this.info = info;

        // проверить наличие пути
        this.id = id; if (id == null || parent.path() == null) path = null; 
        
        // получить путь родительского каталога
        else { short[] parentPath = parent.path(); 
            
            // указать идентификатор файла
            path = new short[parentPath.length + 1]; path[parentPath.length] = id;
            
            // скопировать родительский путь
            System.arraycopy(parentPath, 0, path, 0, path.length - 1);
        }
        // сохранить способ кодирования данных
        this.dataCoding = this.info.getDataCoding(parent.dataCoding()); 
    }
    // каталог файла
    public final DedicatedFile parent() { return parent; } 
    
    // идентификатор файла
    public final Short id() { return id; } 
    // путь файла
    public final short[] path() { return path; }
    
    // способ кодирования данных
    public final DataCoding dataCoding() { return dataCoding; }
    // информация файла
    public final FileControlInformation info() { return info; }
    
    // категория файла
    public int fileCategory() { return FileCategory.UNKNOWN; } 
    // структура файла
    public FileStructure fileStructure() { return FileStructure.UNKNOWN; }
    
    // выделить родительский каталог
    public abstract DedicatedFile selectParent(LogicalChannel channel) throws IOException; 
}
