package aladdin.remoting;
import aladdin.*; 

///////////////////////////////////////////////////////////////////////////
// Задание, выполняемое удаленно
///////////////////////////////////////////////////////////////////////////
public interface IBackgroundTask extends IRefObject
{
    // признак выполнения и идентификатор потока
    boolean isBusy(); long threadID();  
    // признак отмены задания 
    boolean cancellationPending(); 

    // запустить и отменить задание
    void start(Object argument) throws Exception; void cancel();
    
    // обработчик событий
    IBackgroundHandler localHandler(); 
    
    // указать прогресс операции
    void reportProgress(int percentProgress, Object userState);
}
