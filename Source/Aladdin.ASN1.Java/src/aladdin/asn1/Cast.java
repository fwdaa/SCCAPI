package aladdin.asn1;

///////////////////////////////////////////////////////////////////////
// Атрибуты поля в структуре
///////////////////////////////////////////////////////////////////////
public enum Cast
{
    N (0),  // отсутствие атрибутов
    E (1),  // явное приведение типа
    O (2),  // необязательное поле
    EO(3);  // явное приведение типа + необязательное поле

    // конструктор
    private Cast(int value) { intValue = value; } 

    // получить значение
    public int value() { return intValue; } private final int intValue;
}