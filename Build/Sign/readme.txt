Использование сертификатов при сборке:
1) Сертификат Аладдин для подписи кода должен быть установлен Trusted Publishers и ему должен соответствовать личный ключ;
2) Отпечаток сертификата Аладдин для подписи кода указывается в параметрах SignTool; 
3) Сертификаты GlobalSignCodeG3-SHA(XXX)-R(X).cer должны быть установлен в Intermediate Certification Authorities; 
4) Сертификаты GlobalSignRootR(X)-SHA(XXX).cer должны быть установлен в Trusted Root Certification Authorities; 
5) Сертификаты GlobalSignRootR(X)-SHA(XXX)-MS.cer являются кросс-сертификатами от Microsoft и указывается в параметрах SignTool;
6) Сертификат GlobalSignRootR3-SHA256-R1.cer является кросс-сертификатом GlobalSign на сертификат GlobalSignRootR3-SHA256.cer 
     через сертификат GlobalSignRootR1-SHA1.cer и должны быть установлен в Intermediate Certification Authorities;

Сертификаты существуют в трех типах: 
1) SHA1 - для Windows XP, Windows Vista, Windows 7 (без обновления для SHA256); 
2) SHA256 - для Windows XP, Windows Vista, Windows 7 (c обновлением для SHA256), Windows 8;
3) SHA256EV - для Windows 10 (требует online-подписания драйвера). 
