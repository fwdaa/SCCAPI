package aladdin.asn1;

///////////////////////////////////////////////////////////////////////////
// Закодированное BER-представление объекта
///////////////////////////////////////////////////////////////////////////
public interface IEncodable
{
    Tag     tag    ();  // тип объекта
    PC      pc     ();  // способ кодирования
    byte[]  content();  // содержимое объекта
    byte[]  encoded();  // закодированное представление 
}
