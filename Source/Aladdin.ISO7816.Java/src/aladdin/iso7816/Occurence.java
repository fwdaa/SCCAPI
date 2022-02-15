package aladdin.iso7816;

///////////////////////////////////////////////////////////////////////////
// Относительное положение
///////////////////////////////////////////////////////////////////////////
public enum Occurence { FIRST(0), LAST(1), NEXT(2), PREVIOUS(3);

    // конструктор
    private Occurence(int value) { intValue = value; } 
    
    // получить значение
    public int value() { return intValue; } private final int intValue;
}
