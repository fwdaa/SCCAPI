package aladdin.asn1.iso.pkix.ce;
import aladdin.asn1.*;
import aladdin.asn1.Integer; 
import java.io.*; 

//	NoticeNumbers ::= SEQUENCE OF INTEGER

public final class NoticeNumbers extends Sequence<Integer> 
{
    private static final long serialVersionUID = 1257504700148257187L;
    
    // конструктор при раскодировании
    public NoticeNumbers(IEncodable encodable) throws IOException  
    { 
		// вызвать базовую функцию
		super(Integer.class, encodable); 
    }
    // конструктор при закодировании
    public NoticeNumbers(Integer... values) 
    { 
		// вызвать базовую функцию
		super(Integer.class, values); 
    } 
}
