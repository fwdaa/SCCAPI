package aladdin.remoting;
import aladdin.async.*; 

///////////////////////////////////////////////////////////////////////////////
// Обработчик событий BackgroundWorker
///////////////////////////////////////////////////////////////////////////////
public interface IBackgroundHandler 
{
    // обработка уведомлений о прогрессе 
    void onProgressChanged(Object sender, ProgressChangedEventArgs e) throws Exception; 
    // обработка уведомления о завершении
    void onCompleted(Object sender, RunWorkerCompletedEventArgs e) throws Exception; 
}
