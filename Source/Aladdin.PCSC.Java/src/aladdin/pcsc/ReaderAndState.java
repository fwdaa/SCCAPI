package aladdin.pcsc;

///////////////////////////////////////////////////////////////////////
// Состояние считывателя
///////////////////////////////////////////////////////////////////////
public class ReaderAndState 
{
    // конструктор
    public ReaderAndState(String reader, int currentState)
    {
        // указать имя считывателя и текущее состояние
        this.reader = reader; this.currentState = currentState; 

        // инициализировать переменную
        this.eventState = currentState; 
    }
    public String reader;       // имя считывателя
    public int    currentState; // текущее состояние считывателя
    public int    eventState;   // состояние считывателя после изменения
}
