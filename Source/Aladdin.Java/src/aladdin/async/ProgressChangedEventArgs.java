package aladdin.async;

///////////////////////////////////////////////////////////////////////////////
// Provides data for the ProgressChanged event
///////////////////////////////////////////////////////////////////////////////
public class ProgressChangedEventArgs 
{
    // прогресс операции и дополнительные данные
    private final int progressPercentage; private final Object userState;
    
    // конструктор
    public ProgressChangedEventArgs(int progressPercentage, Object userState)
    {
        // сохранить переданные параметры
        this.progressPercentage = progressPercentage; this.userState = userState;
    }    
    // прогресс операции
    public final int progressPercentage() { return progressPercentage; } 
    // дополнительные данные
    public final Object userState() { return userState; } 
}
