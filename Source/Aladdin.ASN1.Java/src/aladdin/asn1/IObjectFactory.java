package aladdin.asn1;
import java.io.*; 

///////////////////////////////////////////////////////////////////////////
// Создание объекта
///////////////////////////////////////////////////////////////////////////
public interface IObjectFactory<T extends IEncodable>
{
    // проверить допустимость типа
    boolean isValidTag(Tag tag); 

    // создать объект
    T decode(IEncodable encodable) throws IOException;

    // проверить корректность объекта
    void validate(IEncodable obj, boolean encode) throws IOException;
}
