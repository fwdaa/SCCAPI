﻿using System;
using System.Collections.Generic;

//  GostR3410-94-ParamSetParameters-t ::= INTEGER (512 | 1024)
//	GOSTR3410ParamSet ::= SEQUENCE {
//		t GostR3410-94-ParamSetParameters-t,
//		p INTEGER,
//		q INTEGER,
//		a INTEGER,
//      validationAlgorithm AlgorithmIdentifier OPTIONAL
//	}

namespace Aladdin.ASN1.GOST
{
    public class GOSTR3410ParamSet1994 : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 

            new ObjectInfo(new ObjectCreator<Integer                     >().Factory(512, 1024), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer                     >().Factory(         ), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer                     >().Factory(         ), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer                     >().Factory(         ), Cast.N), 
		    new ObjectInfo(new ObjectCreator<ASN1.ISO.AlgorithmIdentifier>().Factory(         ), Cast.O) 
	    }; 
	    // конструктор при раскодировании
	    public GOSTR3410ParamSet1994(IEncodable encodable) : base(encodable, info) {}
		
	    // конструктор при закодировании
	    public GOSTR3410ParamSet1994(Integer t, Integer p, 
            Integer q, Integer a, ASN1.ISO.AlgorithmIdentifier validationAlgorithm) 
            : base(info, t, p, q, a, validationAlgorithm) {} 

	    public Integer                      T                   { get { return (Integer                     )this[0]; }} 
	    public Integer                      P                   { get { return (Integer                     )this[1]; }} 
	    public Integer                      Q                   { get { return (Integer                     )this[2]; }}
	    public Integer                      A                   { get { return (Integer                     )this[3]; }} 
	    public ASN1.ISO.AlgorithmIdentifier ValidationAlgorithm { get { return (ASN1.ISO.AlgorithmIdentifier)this[4]; }} 

        ////////////////////////////////////////////////////////////////////////////
	    // Наборы параметров
        ////////////////////////////////////////////////////////////////////////////
	    public static readonly Math.BigInteger Sign512T_94_T = Math.BigInteger.ValueOf(512);
	    public static readonly Math.BigInteger Sign512T_94_P = new Math.BigInteger(1, new byte[] { 
            (byte)0xEE, (byte)0x81, (byte)0x72, (byte)0xAE, 
            (byte)0x89, (byte)0x96, (byte)0x60, (byte)0x8F, 
            (byte)0xB6, (byte)0x93, (byte)0x59, (byte)0xB8, 
            (byte)0x9E, (byte)0xB8, (byte)0x2A, (byte)0x69,  
            (byte)0x85, (byte)0x45, (byte)0x10, (byte)0xE2, 
            (byte)0x97, (byte)0x7A, (byte)0x4D, (byte)0x63, 
            (byte)0xBC, (byte)0x97, (byte)0x32, (byte)0x2C, 
            (byte)0xE5, (byte)0xDC, (byte)0x33, (byte)0x86,  
            (byte)0xEA, (byte)0x0A, (byte)0x12, (byte)0xB3, 
            (byte)0x43, (byte)0xE9, (byte)0x19, (byte)0x0F, 
            (byte)0x23, (byte)0x17, (byte)0x75, (byte)0x39, 
            (byte)0x84, (byte)0x58, (byte)0x39, (byte)0x78,  
            (byte)0x6B, (byte)0xB0, (byte)0xC3, (byte)0x45, 
            (byte)0xD1, (byte)0x65, (byte)0x97, (byte)0x6E, 
            (byte)0xF2, (byte)0x19, (byte)0x5E, (byte)0xC9, 
            (byte)0xB1, (byte)0xC3, (byte)0x79, (byte)0xE3	
        });
	    public static readonly Math.BigInteger Sign512T_94_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0x98, (byte)0x91, (byte)0x5E, (byte)0x7E, 
            (byte)0xC8, (byte)0x26, (byte)0x5E, (byte)0xDF, 
            (byte)0xCD, (byte)0xA3, (byte)0x1E, (byte)0x88, 
            (byte)0xF2, (byte)0x48, (byte)0x09, (byte)0xDD,  
            (byte)0xB0, (byte)0x64, (byte)0xBD, (byte)0xC7, 
            (byte)0x28, (byte)0x5D, (byte)0xD5, (byte)0x0D, 
            (byte)0x72, (byte)0x89, (byte)0xF0, (byte)0xAC, 
            (byte)0x6F, (byte)0x49, (byte)0xDD, (byte)0x2D	
        });
	    public static readonly Math.BigInteger Sign512T_94_A = new Math.BigInteger(1, new byte[] {
            (byte)0x9E, (byte)0x96, (byte)0x03, (byte)0x15, 
            (byte)0x00, (byte)0xC8, (byte)0x77, (byte)0x4A, 
            (byte)0x86, (byte)0x95, (byte)0x82, (byte)0xD4, 
            (byte)0xAF, (byte)0xDE, (byte)0x21, (byte)0x27,  
            (byte)0xAF, (byte)0xAD, (byte)0x25, (byte)0x38, 
            (byte)0xB4, (byte)0xB6, (byte)0x27, (byte)0x0A, 
            (byte)0x6F, (byte)0x7C, (byte)0x88, (byte)0x37, 
            (byte)0xB5, (byte)0x0D, (byte)0x50, (byte)0xF2,  
            (byte)0x06, (byte)0x75, (byte)0x59, (byte)0x84, 
            (byte)0xA4, (byte)0x9E, (byte)0x50, (byte)0x93, 
            (byte)0x04, (byte)0xD6, (byte)0x48, (byte)0xBE, 
            (byte)0x2A, (byte)0xB5, (byte)0xAA, (byte)0xB1,  
            (byte)0x8E, (byte)0xBE, (byte)0x2C, (byte)0xD4, 
            (byte)0x6A, (byte)0xC3, (byte)0xD8, (byte)0x49, 
            (byte)0x5B, (byte)0x14, (byte)0x2A, (byte)0xA6, 
            (byte)0xCE, (byte)0x23, (byte)0xE2, (byte)0x1C	
        }); 
        public static readonly ASN1.ISO.AlgorithmIdentifier Sign512T_94_VP = new ASN1.ISO.AlgorithmIdentifier(
            new ObjectIdentifier(OID.gostR3410_1994_a), new GOSTR3410ValidationParameters(
                new Integer(24265), new Integer(29505), new Integer(2)
        )); 
    
	    // параметры алгоритма
	    public static readonly Math.BigInteger Sign1024A_94_T = Math.BigInteger.ValueOf(1024);
	    public static readonly Math.BigInteger Sign1024A_94_P = new Math.BigInteger(1, new byte[] { 
            (byte)0xB4, (byte)0xE2, (byte)0x5E, (byte)0xFB,
            (byte)0x01, (byte)0x8E, (byte)0x3C, (byte)0x8B, 
            (byte)0x87, (byte)0x50, (byte)0x5E, (byte)0x2A, 
            (byte)0x67, (byte)0x55, (byte)0x3C, (byte)0x5E, 
            (byte)0xDC, (byte)0x56, (byte)0xC2, (byte)0x91, 
            (byte)0x4B, (byte)0x7E, (byte)0x4F, (byte)0x89, 
            (byte)0xD2, (byte)0x3F, (byte)0x03, (byte)0xF0, 
            (byte)0x33, (byte)0x77, (byte)0xE7, (byte)0x0A,  
            (byte)0x29, (byte)0x03, (byte)0x48, (byte)0x9D, 
            (byte)0xD6, (byte)0x0E, (byte)0x78, (byte)0x41, 
            (byte)0x8D, (byte)0x3D, (byte)0x85, (byte)0x1E, 
            (byte)0xDB, (byte)0x53, (byte)0x17, (byte)0xC4,  
            (byte)0x87, (byte)0x1E, (byte)0x40, (byte)0xB0, 
            (byte)0x42, (byte)0x28, (byte)0xC3, (byte)0xB7, 
            (byte)0x90, (byte)0x29, (byte)0x63, (byte)0xC4, 
            (byte)0xB7, (byte)0xD8, (byte)0x5D, (byte)0x52,  
            (byte)0xB9, (byte)0xAA, (byte)0x88, (byte)0xF2, 
            (byte)0xAF, (byte)0xDB, (byte)0xEB, (byte)0x28, 
            (byte)0xDA, (byte)0x88, (byte)0x69, (byte)0xD6, 
            (byte)0xDF, (byte)0x84, (byte)0x6A, (byte)0x1D,  
            (byte)0x98, (byte)0x92, (byte)0x4E, (byte)0x92, 
            (byte)0x55, (byte)0x61, (byte)0xBD, (byte)0x69, 
            (byte)0x30, (byte)0x0B, (byte)0x9D, (byte)0xDD, 
            (byte)0x05, (byte)0xD2, (byte)0x47, (byte)0xB5,
            (byte)0x92, (byte)0x2D, (byte)0x96, (byte)0x7C, 
            (byte)0xBB, (byte)0x02, (byte)0x67, (byte)0x18, 
            (byte)0x81, (byte)0xC5, (byte)0x7D, (byte)0x10, 
            (byte)0xE5, (byte)0xEF, (byte)0x72, (byte)0xD3,  
            (byte)0xE6, (byte)0xDA, (byte)0xD4, (byte)0x22, 
            (byte)0x3D, (byte)0xC8, (byte)0x2A, (byte)0xA1, 
            (byte)0xF7, (byte)0xD0, (byte)0x29, (byte)0x46, 
            (byte)0x51, (byte)0xA4, (byte)0x80, (byte)0xDF    
        });
	    public static readonly Math.BigInteger Sign1024A_94_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0x97, (byte)0x24, (byte)0x32, (byte)0xA4, 
            (byte)0x37, (byte)0x17, (byte)0x8B, (byte)0x30, 
            (byte)0xBD, (byte)0x96, (byte)0x19, (byte)0x5B, 
            (byte)0x77, (byte)0x37, (byte)0x89, (byte)0xAB,  
            (byte)0x2F, (byte)0xFF, (byte)0x15, (byte)0x59, 
            (byte)0x4B, (byte)0x17, (byte)0x6D, (byte)0xD1, 
            (byte)0x75, (byte)0xB6, (byte)0x32, (byte)0x56, 
            (byte)0xEE, (byte)0x5A, (byte)0xF2, (byte)0xCF    
        });
	    public static readonly Math.BigInteger Sign1024A_94_A = new Math.BigInteger(1, new byte[] {
            (byte)0x8F, (byte)0xD3, (byte)0x67, (byte)0x31, 
            (byte)0x23, (byte)0x76, (byte)0x54, (byte)0xBB, 
            (byte)0xE4, (byte)0x1F, (byte)0x5F, (byte)0x1F, 
            (byte)0x84, (byte)0x53, (byte)0xE7, (byte)0x1C, 
            (byte)0xA4, (byte)0x14, (byte)0xFF, (byte)0xC2, 
            (byte)0x2C, (byte)0x25, (byte)0xD9, (byte)0x15, 
            (byte)0x30, (byte)0x9E, (byte)0x5D, (byte)0x2E, 
            (byte)0x62, (byte)0xA2, (byte)0xA2, (byte)0x6C, 
            (byte)0x71, (byte)0x11, (byte)0xF3, (byte)0xFC, 
            (byte)0x79, (byte)0x56, (byte)0x8D, (byte)0xAF, 
            (byte)0xA0, (byte)0x28, (byte)0x04, (byte)0x2F, 
            (byte)0xE1, (byte)0xA5, (byte)0x2A, (byte)0x04, 
            (byte)0x89, (byte)0x80, (byte)0x5C, (byte)0x0D, 
            (byte)0xE9, (byte)0xA1, (byte)0xA4, (byte)0x69, 
            (byte)0xC8, (byte)0x44, (byte)0xC7, (byte)0xCA, 
            (byte)0xBB, (byte)0xEE, (byte)0x62, (byte)0x5C, 
            (byte)0x30, (byte)0x78, (byte)0x88, (byte)0x8C, 
            (byte)0x1D, (byte)0x85, (byte)0xEE, (byte)0xA8, 
            (byte)0x83, (byte)0xF1, (byte)0xAD, (byte)0x5B, 
            (byte)0xC4, (byte)0xE6, (byte)0x77, (byte)0x6E, 
            (byte)0x8E, (byte)0x1A, (byte)0x07, (byte)0x50, 
            (byte)0x91, (byte)0x2D, (byte)0xF6, (byte)0x4F, 
            (byte)0x79, (byte)0x95, (byte)0x64, (byte)0x99, 
            (byte)0xF1, (byte)0xE1, (byte)0x82, (byte)0x47, 
            (byte)0x5B, (byte)0x0B, (byte)0x60, (byte)0xE2, 
            (byte)0x63, (byte)0x2A, (byte)0xDC, (byte)0xD8, 
            (byte)0xCF, (byte)0x94, (byte)0xE9, (byte)0xC5, 
            (byte)0x4F, (byte)0xD1, (byte)0xF3, (byte)0xB1, 
            (byte)0x09, (byte)0xD8, (byte)0x1F, (byte)0x00, 
            (byte)0xBF, (byte)0x2A, (byte)0xB8, (byte)0xCB, 
            (byte)0x86, (byte)0x2A, (byte)0xDF, (byte)0x7D, 
            (byte)0x40, (byte)0xB9, (byte)0x36, (byte)0x9A    
        }); 
	    public static readonly Math.BigInteger Sign1024A_94_C = new Math.BigInteger(1, new byte[] {
            (byte)0xEE, (byte)0x39, (byte)0xAD, (byte)0xB3
        }); 
        public static readonly ASN1.ISO.AlgorithmIdentifier Sign1024A_94_VP = new ASN1.ISO.AlgorithmIdentifier(
            new ObjectIdentifier(OID.gostR3410_1994_bBis), new GOSTR3410ValidationParameters(
                new Integer(1376285941), new Integer(Sign1024A_94_C), null
        )); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger Sign1024B_94_T = Math.BigInteger.ValueOf(1024);
	    public static readonly Math.BigInteger Sign1024B_94_P = new Math.BigInteger(1, new byte[] { 
            (byte)0xC6, (byte)0x97, (byte)0x1F, (byte)0xC5, 
            (byte)0x75, (byte)0x24, (byte)0xB3, (byte)0x0C, 
            (byte)0x90, (byte)0x18, (byte)0xC5, (byte)0xE6, 
            (byte)0x21, (byte)0xDE, (byte)0x15, (byte)0x49, 
            (byte)0x97, (byte)0x36, (byte)0x85, (byte)0x4F, 
            (byte)0x56, (byte)0xA6, (byte)0xF8, (byte)0xAE, 
            (byte)0xE6, (byte)0x5A, (byte)0x7A, (byte)0x40, 
            (byte)0x46, (byte)0x32, (byte)0xB1, (byte)0xBC, 
            (byte)0xF0, (byte)0x34, (byte)0x9F, (byte)0xFC, 
            (byte)0xAF, (byte)0xCB, (byte)0x0A, (byte)0x10, 
            (byte)0x31, (byte)0x77, (byte)0x97, (byte)0x1F, 
            (byte)0xC1, (byte)0x61, (byte)0x2A, (byte)0xDC, 
            (byte)0xDB, (byte)0x8C, (byte)0x8C, (byte)0xC9, 
            (byte)0x38, (byte)0xC7, (byte)0x02, (byte)0x25, 
            (byte)0xC8, (byte)0xFD, (byte)0x12, (byte)0xAF, 
            (byte)0xF0, (byte)0x1B, (byte)0x1D, (byte)0x06, 
            (byte)0x4E, (byte)0x0A, (byte)0xD6, (byte)0xFD, 
            (byte)0xE6, (byte)0xAB, (byte)0x91, (byte)0x59, 
            (byte)0x16, (byte)0x6C, (byte)0xB9, (byte)0xF2, 
            (byte)0xFC, (byte)0x17, (byte)0x1D, (byte)0x92, 
            (byte)0xF0, (byte)0xCC, (byte)0x7B, (byte)0x6A, 
            (byte)0x6B, (byte)0x2C, (byte)0xD7, (byte)0xFA, 
            (byte)0x34, (byte)0x2A, (byte)0xCB, (byte)0xE2, 
            (byte)0xC9, (byte)0x31, (byte)0x5A, (byte)0x42, 
            (byte)0xD5, (byte)0x76, (byte)0xB1, (byte)0xEC, 
            (byte)0xCE, (byte)0x77, (byte)0xA9, (byte)0x63, 
            (byte)0x15, (byte)0x7F, (byte)0x3D, (byte)0x0B, 
            (byte)0xD9, (byte)0x6A, (byte)0x8E, (byte)0xB0, 
            (byte)0xB0, (byte)0xF3, (byte)0x50, (byte)0x2A, 
            (byte)0xD2, (byte)0x38, (byte)0x10, (byte)0x1B, 
            (byte)0x05, (byte)0x11, (byte)0x63, (byte)0x34, 
            (byte)0xF1, (byte)0xE5, (byte)0xB7, (byte)0xAB     
        });
	    public static readonly Math.BigInteger Sign1024B_94_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0xB0, (byte)0x9D, (byte)0x63, (byte)0x4C, 
            (byte)0x10, (byte)0x89, (byte)0x9C, (byte)0xD7, 
            (byte)0xD4, (byte)0xC3, (byte)0xA7, (byte)0x65, 
            (byte)0x74, (byte)0x03, (byte)0xE0, (byte)0x58, 
            (byte)0x10, (byte)0xB0, (byte)0x7C, (byte)0x61, 
            (byte)0xA6, (byte)0x88, (byte)0xBA, (byte)0xB2, 
            (byte)0xC3, (byte)0x7F, (byte)0x47, (byte)0x5E, 
            (byte)0x30, (byte)0x8B, (byte)0x06, (byte)0x07    
        });
	    public static readonly Math.BigInteger Sign1024B_94_A = new Math.BigInteger(1, new byte[] {
            (byte)0x3D, (byte)0x26, (byte)0xB4, (byte)0x67, 
            (byte)0xD9, (byte)0x4A, (byte)0x3F, (byte)0xFC, 
            (byte)0x9D, (byte)0x71, (byte)0xBF, (byte)0x8D, 
            (byte)0xB8, (byte)0x93, (byte)0x40, (byte)0x84, 
            (byte)0x13, (byte)0x72, (byte)0x64, (byte)0xF3, 
            (byte)0xC2, (byte)0xE9, (byte)0xEB, (byte)0x16, 
            (byte)0xDC, (byte)0xA2, (byte)0x14, (byte)0xB8, 
            (byte)0xBC, (byte)0x7C, (byte)0x87, (byte)0x24, 
            (byte)0x85, (byte)0x33, (byte)0x67, (byte)0x44, 
            (byte)0x93, (byte)0x4F, (byte)0xD2, (byte)0xEF, 
            (byte)0x59, (byte)0x43, (byte)0xF9, (byte)0xED, 
            (byte)0x0B, (byte)0x74, (byte)0x5B, (byte)0x90, 
            (byte)0xAA, (byte)0x3E, (byte)0xC8, (byte)0xD7, 
            (byte)0x0C, (byte)0xDC, (byte)0x91, (byte)0x68, 
            (byte)0x24, (byte)0x78, (byte)0xB6, (byte)0x64, 
            (byte)0xA2, (byte)0xE1, (byte)0xF8, (byte)0xFB, 
            (byte)0x56, (byte)0xCE, (byte)0xF2, (byte)0x97, 
            (byte)0x2F, (byte)0xEE, (byte)0x7E, (byte)0xDB, 
            (byte)0x08, (byte)0x4A, (byte)0xF7, (byte)0x46, 
            (byte)0x41, (byte)0x9B, (byte)0x85, (byte)0x4F, 
            (byte)0xAD, (byte)0x02, (byte)0xCC, (byte)0x3E, 
            (byte)0x36, (byte)0x46, (byte)0xFF, (byte)0x2E, 
            (byte)0x1A, (byte)0x18, (byte)0xDD, (byte)0x4B, 
            (byte)0xEB, (byte)0x3C, (byte)0x44, (byte)0xF7,
            (byte)0xF2, (byte)0x74, (byte)0x55, (byte)0x88, 
            (byte)0x02, (byte)0x96, (byte)0x49, (byte)0x67, 
            (byte)0x45, (byte)0x46, (byte)0xCC, (byte)0x91, 
            (byte)0x87, (byte)0xC2, (byte)0x07, (byte)0xFB, 
            (byte)0x8F, (byte)0x2C, (byte)0xEC, (byte)0xE8, 
            (byte)0xE2, (byte)0x29, (byte)0x3F, (byte)0x68, 
            (byte)0x39, (byte)0x5C, (byte)0x47, (byte)0x04, 
            (byte)0xAF, (byte)0x04, (byte)0xBA, (byte)0xB5    
        }); 
	    public static readonly Math.BigInteger Sign1024B_94_D = new Math.BigInteger(1, new byte[] {
            (byte)0xBC, (byte)0x3C, (byte)0xBB, (byte)0xDB, 
            (byte)0x7E, (byte)0x6F, (byte)0x84, (byte)0x82, 
            (byte)0x86, (byte)0xE1, (byte)0x9A, (byte)0xD9, 
            (byte)0xA2, (byte)0x7A, (byte)0x8E, (byte)0x29, 
            (byte)0x7E, (byte)0x5B, (byte)0x71, (byte)0xC5, 
            (byte)0x3D, (byte)0xD9, (byte)0x74, (byte)0xCD, 
            (byte)0xF6, (byte)0x0F, (byte)0x93, (byte)0x73, 
            (byte)0x56, (byte)0xDF, (byte)0x69, (byte)0xCB, 
            (byte)0xC9, (byte)0x7A, (byte)0x30, (byte)0x0C, 
            (byte)0xCC, (byte)0x71, (byte)0x68, (byte)0x5C, 
            (byte)0x55, (byte)0x30, (byte)0x46, (byte)0x14, 
            (byte)0x7F, (byte)0x11, (byte)0x56, (byte)0x8C, 
            (byte)0x4F, (byte)0xDD, (byte)0xF3, (byte)0x63, 
            (byte)0xD9, (byte)0xD8, (byte)0x86, (byte)0x43, 
            (byte)0x83, (byte)0x45, (byte)0xA6, (byte)0x2C, 
            (byte)0x3B, (byte)0x75, (byte)0x96, (byte)0x3D, 
            (byte)0x65, (byte)0x46, (byte)0xAD, (byte)0xFA, 
            (byte)0xBF, (byte)0x31, (byte)0xB3, (byte)0x12, 
            (byte)0x90, (byte)0xD1, (byte)0x2C, (byte)0xAE, 
            (byte)0x65, (byte)0xEC, (byte)0xB8, (byte)0x30, 
            (byte)0x9E, (byte)0xF6, (byte)0x67, (byte)0x82    
        }); 
        public static readonly ASN1.ISO.AlgorithmIdentifier Sign1024B_94_VP = new ASN1.ISO.AlgorithmIdentifier(
            new ObjectIdentifier(OID.gostR3410_1994_bBis), new GOSTR3410ValidationParameters(
                new Integer(1536654555), new Integer(1855361757), new Integer(Sign1024B_94_D)
        )); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger Sign1024C_94_T = Math.BigInteger.ValueOf(1024);
	    public static readonly Math.BigInteger Sign1024C_94_P = new Math.BigInteger(1, new byte[] { 
            (byte)0x9D, (byte)0x88, (byte)0xE6, (byte)0xD7, 
            (byte)0xFE, (byte)0x33, (byte)0x13, (byte)0xBD, 
            (byte)0x2E, (byte)0x74, (byte)0x5C, (byte)0x7C, 
            (byte)0xDD, (byte)0x2A, (byte)0xB9, (byte)0xEE, 
            (byte)0x4A, (byte)0xF3, (byte)0xC8, (byte)0x89, 
            (byte)0x9E, (byte)0x84, (byte)0x7D, (byte)0xE7, 
            (byte)0x4A, (byte)0x33, (byte)0x78, (byte)0x3E, 
            (byte)0xA6, (byte)0x8B, (byte)0xC3, (byte)0x05, 
            (byte)0x88, (byte)0xBA, (byte)0x1F, (byte)0x73, 
            (byte)0x8C, (byte)0x6A, (byte)0xAF, (byte)0x8A, 
            (byte)0xB3, (byte)0x50, (byte)0x53, (byte)0x1F, 
            (byte)0x18, (byte)0x54, (byte)0xC3, (byte)0x83, 
            (byte)0x7C, (byte)0xC3, (byte)0xC8, (byte)0x60, 
            (byte)0xFF, (byte)0xD7, (byte)0xE2, (byte)0xE1, 
            (byte)0x06, (byte)0xC3, (byte)0xF6, (byte)0x3B, 
            (byte)0x3D, (byte)0x8A, (byte)0x4C, (byte)0x03, 
            (byte)0x4C, (byte)0xE7, (byte)0x39, (byte)0x42, 
            (byte)0xA6, (byte)0xC3, (byte)0xD5, (byte)0x85, 
            (byte)0xB5, (byte)0x99, (byte)0xCF, (byte)0x69, 
            (byte)0x5E, (byte)0xD7, (byte)0xA3, (byte)0xC4, 
            (byte)0xA9, (byte)0x3B, (byte)0x2B, (byte)0x94, 
            (byte)0x7B, (byte)0x71, (byte)0x57, (byte)0xBB, 
            (byte)0x1A, (byte)0x1C, (byte)0x04, (byte)0x3A, 
            (byte)0xB4, (byte)0x1E, (byte)0xC8, (byte)0x56, 
            (byte)0x6C, (byte)0x61, (byte)0x45, (byte)0xE9, 
            (byte)0x38, (byte)0xA6, (byte)0x11, (byte)0x90, 
            (byte)0x6D, (byte)0xE0, (byte)0xD3, (byte)0x2E, 
            (byte)0x56, (byte)0x24, (byte)0x94, (byte)0x56, 
            (byte)0x9D, (byte)0x7E, (byte)0x99, (byte)0x9A, 
            (byte)0x0D, (byte)0xDA, (byte)0x5C, (byte)0x87, 
            (byte)0x9B, (byte)0xDD, (byte)0x91, (byte)0xFE, 
            (byte)0x12, (byte)0x4D, (byte)0xF1, (byte)0xE9    
        });
	    public static readonly Math.BigInteger Sign1024C_94_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0xFA, (byte)0xDD, (byte)0x19, (byte)0x7A, 
            (byte)0xBD, (byte)0x19, (byte)0xA1, (byte)0xB4, 
            (byte)0x65, (byte)0x3E, (byte)0xEC, (byte)0xF7, 
            (byte)0xEC, (byte)0xA4, (byte)0xD6, (byte)0xA2, 
            (byte)0x2B, (byte)0x1F, (byte)0x7F, (byte)0x89, 
            (byte)0x3B, (byte)0x64, (byte)0x1F, (byte)0x90, 
            (byte)0x16, (byte)0x41, (byte)0xFB, (byte)0xB5, 
            (byte)0x55, (byte)0x35, (byte)0x4F, (byte)0xAF    
        });
	    public static readonly Math.BigInteger Sign1024C_94_A = new Math.BigInteger(1, new byte[] {
            (byte)0x74, (byte)0x47, (byte)0xED, (byte)0x71, 
            (byte)0x56, (byte)0x31, (byte)0x05, (byte)0x99, 
            (byte)0x07, (byte)0x0B, (byte)0x12, (byte)0x60, 
            (byte)0x99, (byte)0x47, (byte)0xA5, (byte)0xC8, 
            (byte)0xC8, (byte)0xA8, (byte)0x62, (byte)0x5C, 
            (byte)0xF1, (byte)0xCF, (byte)0x25, (byte)0x2B, 
            (byte)0x40, (byte)0x7B, (byte)0x33, (byte)0x1F, 
            (byte)0x93, (byte)0xD6, (byte)0x39, (byte)0xDD, 
            (byte)0xD1, (byte)0xBA, (byte)0x39, (byte)0x26, 
            (byte)0x56, (byte)0xDE, (byte)0xCA, (byte)0x99, 
            (byte)0x2D, (byte)0xD0, (byte)0x35, (byte)0x35, 
            (byte)0x43, (byte)0x29, (byte)0xA1, (byte)0xE9, 
            (byte)0x5A, (byte)0x6E, (byte)0x32, (byte)0xD6, 
            (byte)0xF4, (byte)0x78, (byte)0x82, (byte)0xD9, 
            (byte)0x60, (byte)0xB8, (byte)0xF1, (byte)0x0A, 
            (byte)0xCA, (byte)0xFF, (byte)0x79, (byte)0x6D, 
            (byte)0x13, (byte)0xCD, (byte)0x96, (byte)0x11, 
            (byte)0xF8, (byte)0x53, (byte)0xDA, (byte)0xB6, 
            (byte)0xD2, (byte)0x62, (byte)0x34, (byte)0x83, 
            (byte)0xE4, (byte)0x67, (byte)0x88, (byte)0x70, 
            (byte)0x84, (byte)0x93, (byte)0x93, (byte)0x7A, 
            (byte)0x1A, (byte)0x29, (byte)0x44, (byte)0x25, 
            (byte)0x98, (byte)0xAE, (byte)0xC2, (byte)0xE0, 
            (byte)0x74, (byte)0x20, (byte)0x22, (byte)0x56,
            (byte)0x34, (byte)0x40, (byte)0xFE, (byte)0x9C, 
            (byte)0x18, (byte)0x74, (byte)0x0E, (byte)0xCE, 
            (byte)0x67, (byte)0x65, (byte)0xAC, (byte)0x05, 
            (byte)0xFA, (byte)0xF0, (byte)0x24, (byte)0xA6, 
            (byte)0x4B, (byte)0x02, (byte)0x6E, (byte)0x7E, 
            (byte)0x40, (byte)0x88, (byte)0x40, (byte)0x81, 
            (byte)0x9E, (byte)0x96, (byte)0x2E, (byte)0x7E, 
            (byte)0x5F, (byte)0x40, (byte)0x1A, (byte)0xE3    
        }); 
	    public static readonly Math.BigInteger Sign1024C_94_C = new Math.BigInteger(1, new byte[] {
            (byte)0xB5, (byte)0x0A, (byte)0x82, (byte)0x6D    
        }); 
	    public static readonly Math.BigInteger Sign1024C_94_D = new Math.BigInteger(1, new byte[] {
            (byte)0x7F, (byte)0x57, (byte)0x5E, (byte)0x81, 
            (byte)0x94, (byte)0xBC, (byte)0x5B, (byte)0xDF
        }); 
        public static readonly ASN1.ISO.AlgorithmIdentifier Sign1024C_94_VP = new ASN1.ISO.AlgorithmIdentifier(
            new ObjectIdentifier(OID.gostR3410_1994_bBis), new GOSTR3410ValidationParameters(
                new Integer(1132758852), new Integer(Sign1024C_94_C), new Integer(Sign1024C_94_D)
        )); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger Sign1024D_94_T = Math.BigInteger.ValueOf(1024);
	    public static readonly Math.BigInteger Sign1024D_94_P = new Math.BigInteger(1, new byte[] { 
            (byte)0x80, (byte)0xF1, (byte)0x02, (byte)0xD3, 
            (byte)0x2B, (byte)0x0F, (byte)0xD1, (byte)0x67, 
            (byte)0xD0, (byte)0x69, (byte)0xC2, (byte)0x7A, 
            (byte)0x30, (byte)0x7A, (byte)0xDA, (byte)0xD2, 
            (byte)0xC4, (byte)0x66, (byte)0x09, (byte)0x19, 
            (byte)0x04, (byte)0xDB, (byte)0xAA, (byte)0x55, 
            (byte)0xD5, (byte)0xB8, (byte)0xCC, (byte)0x70, 
            (byte)0x26, (byte)0xF2, (byte)0xF7, (byte)0xA1, 
            (byte)0x91, (byte)0x9B, (byte)0x89, (byte)0x0C, 
            (byte)0xB6, (byte)0x52, (byte)0xC4, (byte)0x0E, 
            (byte)0x05, (byte)0x4E, (byte)0x1E, (byte)0x93, 
            (byte)0x06, (byte)0x73, (byte)0x5B, (byte)0x43, 
            (byte)0xD7, (byte)0xB2, (byte)0x79, (byte)0xED, 
            (byte)0xDF, (byte)0x91, (byte)0x02, (byte)0x00, 
            (byte)0x1C, (byte)0xD9, (byte)0xE1, (byte)0xA8, 
            (byte)0x31, (byte)0xFE, (byte)0x8A, (byte)0x16, 
            (byte)0x3E, (byte)0xED, (byte)0x89, (byte)0xAB, 
            (byte)0x07, (byte)0xCF, (byte)0x2A, (byte)0xBE, 
            (byte)0x82, (byte)0x42, (byte)0xAC, (byte)0x9D, 
            (byte)0xED, (byte)0xDD, (byte)0xBF, (byte)0x98, 
            (byte)0xD6, (byte)0x2C, (byte)0xDD, (byte)0xD1, 
            (byte)0xEA, (byte)0x4F, (byte)0x5F, (byte)0x15, 
            (byte)0xD3, (byte)0xA4, (byte)0x2A, (byte)0x66, 
            (byte)0x77, (byte)0xBD, (byte)0xD2, (byte)0x93, 
            (byte)0xB2, (byte)0x42, (byte)0x60, (byte)0xC0, 
            (byte)0xF2, (byte)0x7C, (byte)0x0F, (byte)0x1D, 
            (byte)0x15, (byte)0x94, (byte)0x86, (byte)0x14, 
            (byte)0xD5, (byte)0x67, (byte)0xB6, (byte)0x6F, 
            (byte)0xA9, (byte)0x02, (byte)0xBA, (byte)0xA1, 
            (byte)0x1A, (byte)0x69, (byte)0xAE, (byte)0x3B, 
            (byte)0xCE, (byte)0xAD, (byte)0xBB, (byte)0x83, 
            (byte)0xE3, (byte)0x99, (byte)0xC9, (byte)0xB5    
        });
	    public static readonly Math.BigInteger Sign1024D_94_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0xF0, (byte)0xF5, (byte)0x44, (byte)0xC4, 
            (byte)0x18, (byte)0xAA, (byte)0xC2, (byte)0x34, 
            (byte)0xF6, (byte)0x83, (byte)0xF0, (byte)0x33, 
            (byte)0x51, (byte)0x1B, (byte)0x65, (byte)0xC2, 
            (byte)0x16, (byte)0x51, (byte)0xA6, (byte)0x07, 
            (byte)0x8B, (byte)0xDA, (byte)0x2D, (byte)0x69, 
            (byte)0xBB, (byte)0x9F, (byte)0x73, (byte)0x28, 
            (byte)0x67, (byte)0x50, (byte)0x21, (byte)0x49    
        });
	    public static readonly Math.BigInteger Sign1024D_94_A = new Math.BigInteger(1, new byte[] {
            (byte)0x6B, (byte)0xCC, (byte)0x0B, (byte)0x4F, 
            (byte)0xAD, (byte)0xB3, (byte)0x88, (byte)0x9C, 
            (byte)0x1E, (byte)0x06, (byte)0xAD, (byte)0xD2, 
            (byte)0x3C, (byte)0xC0, (byte)0x9B, (byte)0x8A, 
            (byte)0xB6, (byte)0xEC, (byte)0xDE, (byte)0xDF, 
            (byte)0x73, (byte)0xF0, (byte)0x46, (byte)0x32, 
            (byte)0x59, (byte)0x5E, (byte)0xE4, (byte)0x25, 
            (byte)0x00, (byte)0x05, (byte)0xD6, (byte)0xAF, 
            (byte)0x5F, (byte)0x5A, (byte)0xDE, (byte)0x44, 
            (byte)0xCB, (byte)0x1E, (byte)0x26, (byte)0xE6, 
            (byte)0x26, (byte)0x3C, (byte)0x67, (byte)0x23, 
            (byte)0x47, (byte)0xCF, (byte)0xA2, (byte)0x6F, 
            (byte)0x9E, (byte)0x93, (byte)0x93, (byte)0x68, 
            (byte)0x1E, (byte)0x6B, (byte)0x75, (byte)0x97, 
            (byte)0x33, (byte)0x78, (byte)0x4C, (byte)0xDE, 
            (byte)0x5D, (byte)0xBD, (byte)0x9A, (byte)0x14, 
            (byte)0xA3, (byte)0x93, (byte)0x69, (byte)0xDF, 
            (byte)0xD9, (byte)0x9F, (byte)0xA8, (byte)0x5C, 
            (byte)0xC0, (byte)0xD1, (byte)0x02, (byte)0x41, 
            (byte)0xC4, (byte)0x01, (byte)0x03, (byte)0x43, 
            (byte)0xF3, (byte)0x4A, (byte)0x91, (byte)0x39, 
            (byte)0x3A, (byte)0x70, (byte)0x6C, (byte)0xF1, 
            (byte)0x26, (byte)0x77, (byte)0xCB, (byte)0xFA, 
            (byte)0x1F, (byte)0x57, (byte)0x8D, (byte)0x6B, 
            (byte)0x6C, (byte)0xFB, (byte)0xE8, (byte)0xA1, 
            (byte)0x24, (byte)0x2C, (byte)0xFC, (byte)0xC9, 
            (byte)0x4B, (byte)0x3B, (byte)0x65, (byte)0x3A, 
            (byte)0x47, (byte)0x6E, (byte)0x14, (byte)0x5E, 
            (byte)0x38, (byte)0x62, (byte)0xC1, (byte)0x8C, 
            (byte)0xC3, (byte)0xFE, (byte)0xD8, (byte)0x25, 
            (byte)0x7C, (byte)0xFE, (byte)0xF7, (byte)0x4C,
            (byte)0xDB, (byte)0x20, (byte)0x5B, (byte)0xF1    
        }); 
	    public static readonly Math.BigInteger Sign1024D_94_C = new Math.BigInteger(1, new byte[] {
            (byte)0xA0, (byte)0xE9, (byte)0xDE, (byte)0x4B    
        }); 
	    public static readonly Math.BigInteger Sign1024D_94_D = new Math.BigInteger(1, new byte[] {
            (byte)0x41, (byte)0xAB, (byte)0x97, (byte)0x85, 
            (byte)0x7F, (byte)0x42, (byte)0x61, (byte)0x43, 
            (byte)0x55, (byte)0xD3, (byte)0x2D, (byte)0xB0, 
            (byte)0xB1, (byte)0x06, (byte)0x9F, (byte)0x10, 
            (byte)0x9A, (byte)0x4D, (byte)0xA2, (byte)0x83, 
            (byte)0x67, (byte)0x6C, (byte)0x7C, (byte)0x53, 
            (byte)0xA6, (byte)0x81, (byte)0x85, (byte)0xB4
        }); 
        public static readonly ASN1.ISO.AlgorithmIdentifier Sign1024D_94_VP = new ASN1.ISO.AlgorithmIdentifier(
            new ObjectIdentifier(OID.gostR3410_1994_bBis), new GOSTR3410ValidationParameters(
                new Integer(333089693), new Integer(Sign1024C_94_D), new Integer(Sign1024D_94_D)
        )); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger Keyx1024A_94_T = Math.BigInteger.ValueOf(1024);
	    public static readonly Math.BigInteger Keyx1024A_94_P = new Math.BigInteger(1, new byte[] { 
            (byte)0xCA, (byte)0x3B, (byte)0x3F, (byte)0x2E, 
            (byte)0xEE, (byte)0x9F, (byte)0xD4, (byte)0x63, 
            (byte)0x17, (byte)0xD4, (byte)0x95, (byte)0x95, 
            (byte)0xA9, (byte)0xE7, (byte)0x51, (byte)0x8E, 
            (byte)0x6C, (byte)0x63, (byte)0xD8, (byte)0xF4, 
            (byte)0xEB, (byte)0x4D, (byte)0x22, (byte)0xD1, 
            (byte)0x0D, (byte)0x28, (byte)0xAF, (byte)0x0B, 
            (byte)0x88, (byte)0x39, (byte)0xF0, (byte)0x79, 
            (byte)0xF8, (byte)0x28, (byte)0x9E, (byte)0x60, 
            (byte)0x3B, (byte)0x03, (byte)0x53, (byte)0x07, 
            (byte)0x84, (byte)0xB9, (byte)0xBB, (byte)0x5A, 
            (byte)0x1E, (byte)0x76, (byte)0x85, (byte)0x9E, 
            (byte)0x48, (byte)0x50, (byte)0xC6, (byte)0x70, 
            (byte)0xC7, (byte)0xB7, (byte)0x1C, (byte)0x0D, 
            (byte)0xF8, (byte)0x4C, (byte)0xA3, (byte)0xE0, 
            (byte)0xD6, (byte)0xC1, (byte)0x77, (byte)0xFE, 
            (byte)0x9F, (byte)0x78, (byte)0xA9, (byte)0xD8, 
            (byte)0x43, (byte)0x32, (byte)0x30, (byte)0xA8, 
            (byte)0x83, (byte)0xCD, (byte)0x82, (byte)0xA2, 
            (byte)0xB2, (byte)0xB5, (byte)0xC7, (byte)0xA3, 
            (byte)0x30, (byte)0x69, (byte)0x80, (byte)0x27, 
            (byte)0x85, (byte)0x70, (byte)0xCD, (byte)0xB7, 
            (byte)0x9B, (byte)0xF0, (byte)0x10, (byte)0x74, 
            (byte)0xA6, (byte)0x9C, (byte)0x96, (byte)0x23, 
            (byte)0x34, (byte)0x88, (byte)0x24, (byte)0xB0, 
            (byte)0xC5, (byte)0x37, (byte)0x91, (byte)0xD5, 
            (byte)0x3C, (byte)0x6A, (byte)0x78, (byte)0xCA, 
            (byte)0xB6, (byte)0x9E, (byte)0x1C, (byte)0xFB, 
            (byte)0x28, (byte)0x36, (byte)0x86, (byte)0x11, 
            (byte)0xA3, (byte)0x97, (byte)0xF5, (byte)0x0F, 
            (byte)0x54, (byte)0x1E, (byte)0x16, (byte)0xDB, 
            (byte)0x34, (byte)0x8D, (byte)0xBE, (byte)0x5F    
        });
	    public static readonly Math.BigInteger Keyx1024A_94_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0xCA, (byte)0xE4, (byte)0xD8, (byte)0x5F, 
            (byte)0x80, (byte)0xC1, (byte)0x47, (byte)0x70, 
            (byte)0x4B, (byte)0x0C, (byte)0xA4, (byte)0x8E, 
            (byte)0x85, (byte)0xFB, (byte)0x00, (byte)0xA9, 
            (byte)0x05, (byte)0x7A, (byte)0xA4, (byte)0xAC, 
            (byte)0xC4, (byte)0x46, (byte)0x68, (byte)0xE1, 
            (byte)0x7F, (byte)0x19, (byte)0x96, (byte)0xD7, 
            (byte)0x15, (byte)0x26, (byte)0x90, (byte)0xD9    
        });
	    public static readonly Math.BigInteger Keyx1024A_94_A = new Math.BigInteger(1, new byte[] {
            (byte)0xBE, (byte)0x27, (byte)0xD6, (byte)0x52, 
            (byte)0xF2, (byte)0xF1, (byte)0xE3, (byte)0x39, 
            (byte)0xDA, (byte)0x73, (byte)0x42, (byte)0x11, 
            (byte)0xB8, (byte)0x5B, (byte)0x06, (byte)0xAE, 
            (byte)0x4D, (byte)0xE2, (byte)0x36, (byte)0xAA, 
            (byte)0x8F, (byte)0xBE, (byte)0xEB, (byte)0x3F, 
            (byte)0x1A, (byte)0xDC, (byte)0xC5, (byte)0x2C, 
            (byte)0xD4, (byte)0x38, (byte)0x53, (byte)0x77, 
            (byte)0x7E, (byte)0x83, (byte)0x4A, (byte)0x6A, 
            (byte)0x51, (byte)0x81, (byte)0x38, (byte)0x67, 
            (byte)0x8A, (byte)0x8A, (byte)0xDB, (byte)0xD3, 
            (byte)0xA5, (byte)0x5C, (byte)0x70, (byte)0xA7, 
            (byte)0xEA, (byte)0xB1, (byte)0xBA, (byte)0x7A, 
            (byte)0x07, (byte)0x19, (byte)0x54, (byte)0x86, 
            (byte)0x77, (byte)0xAA, (byte)0xF4, (byte)0xE6, 
            (byte)0x09, (byte)0xFF, (byte)0xB4, (byte)0x7F, 
            (byte)0x6B, (byte)0x9D, (byte)0x7E, (byte)0x45, 
            (byte)0xB0, (byte)0xD0, (byte)0x6D, (byte)0x83, 
            (byte)0xD7, (byte)0xAD, (byte)0xC5, (byte)0x33, 
            (byte)0x10, (byte)0xAB, (byte)0xD8, (byte)0x57, 
            (byte)0x83, (byte)0xE7, (byte)0x31, (byte)0x7F, 
            (byte)0x7E, (byte)0xC7, (byte)0x32, (byte)0x68, 
            (byte)0xB6, (byte)0xA9, (byte)0xC0, (byte)0x8D, 
            (byte)0x26, (byte)0x0B, (byte)0x85, (byte)0xD8, 
            (byte)0x48, (byte)0x56, (byte)0x96, (byte)0xCA, 
            (byte)0x39, (byte)0xC1, (byte)0x7B, (byte)0x17, 
            (byte)0xF0, (byte)0x44, (byte)0xD1, (byte)0xE0, 
            (byte)0x50, (byte)0x48, (byte)0x90, (byte)0x36, 
            (byte)0xAB, (byte)0xD3, (byte)0x81, (byte)0xC5, 
            (byte)0xE6, (byte)0xBF, (byte)0x82, (byte)0xBA, 
            (byte)0x35, (byte)0x2A, (byte)0x1A, (byte)0xFF, 
            (byte)0x13, (byte)0x66, (byte)0x01, (byte)0xAF    
        }); 
	    public static readonly Math.BigInteger Keyx1024A_94_X0 = new Math.BigInteger(1, new byte[] {
            (byte)0xD0, (byte)0x5E, (byte)0x9F, (byte)0x14
        }); 
	    public static readonly Math.BigInteger Keyx1024A_94_D = new Math.BigInteger(1, new byte[] {
            (byte)0x35, (byte)0xAB, (byte)0x87, (byte)0x53, 
            (byte)0x99, (byte)0xCD, (byte)0xA3, (byte)0x3C, 
            (byte)0x14, (byte)0x6C, (byte)0xA6, (byte)0x29, 
            (byte)0x66, (byte)0x0E, (byte)0x5A, (byte)0x5E, 
            (byte)0x5C, (byte)0x07, (byte)0x71, (byte)0x4C, 
            (byte)0xA3, (byte)0x26, (byte)0xDB, (byte)0x03, 
            (byte)0x2D, (byte)0xD6, (byte)0x75, (byte)0x19, 
            (byte)0x95, (byte)0xCD, (byte)0xB9, (byte)0x0A, 
            (byte)0x61, (byte)0x2B, (byte)0x92, (byte)0x28, 
            (byte)0x93, (byte)0x2D, (byte)0x83, (byte)0x02, 
            (byte)0x70, (byte)0x4E, (byte)0xC2, (byte)0x4A, 
            (byte)0x5D, (byte)0xEF, (byte)0x77, (byte)0x39, 
            (byte)0xC5, (byte)0x81, (byte)0x3D, (byte)0x83    
        }); 
        public static readonly ASN1.ISO.AlgorithmIdentifier Keyx1024A_94_VP = new ASN1.ISO.AlgorithmIdentifier(
            new ObjectIdentifier(OID.gostR3410_1994_bBis), new GOSTR3410ValidationParameters(
                new Integer(Keyx1024A_94_X0), new Integer(1177570399), new Integer(Keyx1024A_94_D)
        )); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger Keyx1024B_94_T = Math.BigInteger.ValueOf(1024);
	    public static readonly Math.BigInteger Keyx1024B_94_P = new Math.BigInteger(1, new byte[] { 
            (byte)0x92, (byte)0x86, (byte)0xDB, (byte)0xDA, 
            (byte)0x91, (byte)0xEC, (byte)0xCF, (byte)0xC3, 
            (byte)0x06, (byte)0x0A, (byte)0xA5, (byte)0x59, 
            (byte)0x83, (byte)0x18, (byte)0xE2, (byte)0xA6, 
            (byte)0x39, (byte)0xF5, (byte)0xBA, (byte)0x90, 
            (byte)0xA4, (byte)0xCA, (byte)0x65, (byte)0x61, 
            (byte)0x57, (byte)0xB2, (byte)0x67, (byte)0x3F, 
            (byte)0xB1, (byte)0x91, (byte)0xCD, (byte)0x05, 
            (byte)0x89, (byte)0xEE, (byte)0x05, (byte)0xF4, 
            (byte)0xCE, (byte)0xF1, (byte)0xBD, (byte)0x13, 
            (byte)0x50, (byte)0x84, (byte)0x08, (byte)0x27, 
            (byte)0x14, (byte)0x58, (byte)0xC3, (byte)0x08, 
            (byte)0x51, (byte)0xCE, (byte)0x7A, (byte)0x4E, 
            (byte)0xF5, (byte)0x34, (byte)0x74, (byte)0x2B, 
            (byte)0xFB, (byte)0x11, (byte)0xF4, (byte)0x74, 
            (byte)0x3C, (byte)0x8F, (byte)0x78, (byte)0x7B, 
            (byte)0x11, (byte)0x19, (byte)0x3B, (byte)0xA3, 
            (byte)0x04, (byte)0xC0, (byte)0xE6, (byte)0xBC, 
            (byte)0xA2, (byte)0x57, (byte)0x01, (byte)0xBF, 
            (byte)0x88, (byte)0xAF, (byte)0x1C, (byte)0xB9, 
            (byte)0xB8, (byte)0xFD, (byte)0x47, (byte)0x11, 
            (byte)0xD8, (byte)0x9F, (byte)0x88, (byte)0xE3, 
            (byte)0x2B, (byte)0x37, (byte)0xD9, (byte)0x53, 
            (byte)0x16, (byte)0x54, (byte)0x1B, (byte)0xF1, 
            (byte)0xE5, (byte)0xDB, (byte)0xB4, (byte)0x98, 
            (byte)0x9B, (byte)0x3D, (byte)0xF1, (byte)0x36, 
            (byte)0x59, (byte)0xB8, (byte)0x8C, (byte)0x0F, 
            (byte)0x97, (byte)0xA3, (byte)0xC1, (byte)0x08, 
            (byte)0x7B, (byte)0x9F, (byte)0x2D, (byte)0x53, 
            (byte)0x17, (byte)0xD5, (byte)0x57, (byte)0xDC, 
            (byte)0xD4, (byte)0xAF, (byte)0xC6, (byte)0xD0, 
            (byte)0xA7, (byte)0x54, (byte)0xE2, (byte)0x79    
        });
	    public static readonly Math.BigInteger Keyx1024B_94_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0xC9, (byte)0x66, (byte)0xE9, (byte)0xB3, 
            (byte)0xB8, (byte)0xB7, (byte)0xCD, (byte)0xD8, 
            (byte)0x2F, (byte)0xF0, (byte)0xF8, (byte)0x3A, 
            (byte)0xF8, (byte)0x70, (byte)0x36, (byte)0xC3, 
            (byte)0x8F, (byte)0x42, (byte)0x23, (byte)0x8E, 
            (byte)0xC5, (byte)0x0A, (byte)0x87, (byte)0x6C, 
            (byte)0xD3, (byte)0x90, (byte)0xE4, (byte)0x3D, 
            (byte)0x67, (byte)0xB6, (byte)0x01, (byte)0x3F    
        });
	    public static readonly Math.BigInteger Keyx1024B_94_A = new Math.BigInteger(1, new byte[] {
            (byte)0x7E, (byte)0x9C, (byte)0x30, (byte)0x96, 
            (byte)0x67, (byte)0x6F, (byte)0x51, (byte)0xE3, 
            (byte)0xB2, (byte)0xF9, (byte)0x88, (byte)0x4C, 
            (byte)0xF0, (byte)0xAC, (byte)0x21, (byte)0x56, 
            (byte)0x77, (byte)0x94, (byte)0x96, (byte)0xF4, 
            (byte)0x10, (byte)0xE0, (byte)0x49, (byte)0xCE, 
            (byte)0xD7, (byte)0xE5, (byte)0x3D, (byte)0x8B, 
            (byte)0x7B, (byte)0x5B, (byte)0x36, (byte)0x6B, 
            (byte)0x1A, (byte)0x60, (byte)0x08, (byte)0xE5, 
            (byte)0x19, (byte)0x66, (byte)0x05, (byte)0xA5, 
            (byte)0x5E, (byte)0x89, (byte)0xC3, (byte)0x19, 
            (byte)0x0D, (byte)0xAB, (byte)0xF8, (byte)0x0B, 
            (byte)0x9F, (byte)0x11, (byte)0x63, (byte)0xC9, 
            (byte)0x79, (byte)0xFC, (byte)0xD1, (byte)0x83, 
            (byte)0x28, (byte)0xDA, (byte)0xE5, (byte)0xE9, 
            (byte)0x04, (byte)0x88, (byte)0x11, (byte)0xB3, 
            (byte)0x70, (byte)0x10, (byte)0x7B, (byte)0xB7, 
            (byte)0x71, (byte)0x5F, (byte)0x82, (byte)0x09, 
            (byte)0x1B, (byte)0xB9, (byte)0xDE, (byte)0x0E, 
            (byte)0x33, (byte)0xEE, (byte)0x2F, (byte)0xED,
            (byte)0x62, (byte)0x55, (byte)0x47, (byte)0x4F, 
            (byte)0x87, (byte)0x69, (byte)0xFC, (byte)0xE5, 
            (byte)0xEA, (byte)0xFA, (byte)0xEE, (byte)0xF1, 
            (byte)0xCB, (byte)0x5A, (byte)0x32, (byte)0xE0, 
            (byte)0xD5, (byte)0xC6, (byte)0xC2, (byte)0xF0, 
            (byte)0xFC, (byte)0x0B, (byte)0x34, (byte)0x47, 
            (byte)0x07, (byte)0x29, (byte)0x47, (byte)0xF5, 
            (byte)0xB4, (byte)0xC3, (byte)0x87, (byte)0x66,
            (byte)0x69, (byte)0x93, (byte)0xA3, (byte)0x33, 
            (byte)0xFC, (byte)0x06, (byte)0x56, (byte)0x8E, 
            (byte)0x53, (byte)0x4A, (byte)0xD5, (byte)0x6D, 
            (byte)0x23, (byte)0x38, (byte)0xD7, (byte)0x29    
        }); 
	    public static readonly Math.BigInteger Keyx1024B_94_C = new Math.BigInteger(1, new byte[] {
            (byte)0xD3, (byte)0x1A, (byte)0x4F, (byte)0xF7    
        }); 
	    public static readonly Math.BigInteger Keyx1024B_94_D = new Math.BigInteger(1, new byte[] {
            (byte)0x7E, (byte)0xC1, (byte)0x23, (byte)0xD1, 
            (byte)0x61, (byte)0x47, (byte)0x77, (byte)0x62, 
            (byte)0x83, (byte)0x8C, (byte)0x2B, (byte)0xEA, 
            (byte)0x9D, (byte)0xBD, (byte)0xF3, (byte)0x30, 
            (byte)0x74, (byte)0xAF, (byte)0x6D, (byte)0x41, 
            (byte)0xD1, (byte)0x08, (byte)0xA0, (byte)0x66, 
            (byte)0xA1, (byte)0xE7, (byte)0xA0, (byte)0x7A, 
            (byte)0xB3, (byte)0x04, (byte)0x8D, (byte)0xE2    
        }); 
        public static readonly ASN1.ISO.AlgorithmIdentifier Keyx1024B_94_VP = new ASN1.ISO.AlgorithmIdentifier(
            new ObjectIdentifier(OID.gostR3410_1994_bBis), new GOSTR3410ValidationParameters(
                new Integer(2046851076), new Integer(Keyx1024B_94_C), new Integer(Keyx1024B_94_D)
        )); 
	    // параметры алгоритма
	    public static readonly Math.BigInteger Keyx1024C_94_T = Math.BigInteger.ValueOf(1024);
	    public static readonly Math.BigInteger Keyx1024C_94_P = new Math.BigInteger(1, new byte[] { 
            (byte)0xB1, (byte)0x94, (byte)0x03, (byte)0x6A, 
            (byte)0xCE, (byte)0x14, (byte)0x13, (byte)0x9D, 
            (byte)0x36, (byte)0xD6, (byte)0x42, (byte)0x95, 
            (byte)0xAE, (byte)0x6C, (byte)0x50, (byte)0xFC, 
            (byte)0x4B, (byte)0x7D, (byte)0x65, (byte)0xD8, 
            (byte)0xB3, (byte)0x40, (byte)0x71, (byte)0x13, 
            (byte)0x66, (byte)0xCA, (byte)0x93, (byte)0xF3, 
            (byte)0x83, (byte)0x65, (byte)0x39, (byte)0x08, 
            (byte)0xEE, (byte)0x63, (byte)0x7B, (byte)0xE4, 
            (byte)0x28, (byte)0x05, (byte)0x1D, (byte)0x86, 
            (byte)0x61, (byte)0x26, (byte)0x70, (byte)0xAD, 
            (byte)0x7B, (byte)0x40, (byte)0x2C, (byte)0x09, 
            (byte)0xB8, (byte)0x20, (byte)0xFA, (byte)0x77, 
            (byte)0xD9, (byte)0xDA, (byte)0x29, (byte)0xC8, 
            (byte)0x11, (byte)0x1A, (byte)0x84, (byte)0x96, 
            (byte)0xDA, (byte)0x6C, (byte)0x26, (byte)0x1A, 
            (byte)0x53, (byte)0xED, (byte)0x25, (byte)0x2E, 
            (byte)0x4D, (byte)0x8A, (byte)0x69, (byte)0xA2, 
            (byte)0x03, (byte)0x76, (byte)0xE6, (byte)0xAD, 
            (byte)0xDB, (byte)0x3B, (byte)0xDC, (byte)0xD3, 
            (byte)0x31, (byte)0x74, (byte)0x9A, (byte)0x49, 
            (byte)0x1A, (byte)0x18, (byte)0x4B, (byte)0x8F, 
            (byte)0xDA, (byte)0x6D, (byte)0x84, (byte)0xC3, 
            (byte)0x1C, (byte)0xF0, (byte)0x5F, (byte)0x91, 
            (byte)0x19, (byte)0xB5, (byte)0xED, (byte)0x35, 
            (byte)0x24, (byte)0x6E, (byte)0xA4, (byte)0x56, 
            (byte)0x2D, (byte)0x85, (byte)0x92, (byte)0x8B, 
            (byte)0xA1, (byte)0x13, (byte)0x6A, (byte)0x8D, 
            (byte)0x0E, (byte)0x5A, (byte)0x7E, (byte)0x5C, 
            (byte)0x76, (byte)0x4B, (byte)0xA8, (byte)0x90, 
            (byte)0x20, (byte)0x29, (byte)0xA1, (byte)0x33, 
            (byte)0x6C, (byte)0x63, (byte)0x1A, (byte)0x1D    
        });
	    public static readonly Math.BigInteger Keyx1024C_94_Q = new Math.BigInteger(1, new byte[] { 
            (byte)0x96, (byte)0x12, (byte)0x04, (byte)0x77, 
            (byte)0xDF, (byte)0x0F, (byte)0x38, (byte)0x96, 
            (byte)0x62, (byte)0x8E, (byte)0x6F, (byte)0x4A, 
            (byte)0x88, (byte)0xD8, (byte)0x3C, (byte)0x93, 
            (byte)0x20, (byte)0x4C, (byte)0x21, (byte)0x0F, 
            (byte)0xF2, (byte)0x62, (byte)0xBC, (byte)0xCB, 
            (byte)0x7D, (byte)0xAE, (byte)0x45, (byte)0x03, 
            (byte)0x55, (byte)0x12, (byte)0x52, (byte)0x59    
        });
	    public static readonly Math.BigInteger Keyx1024C_94_A = new Math.BigInteger(1, new byte[] {
            (byte)0x3F, (byte)0x18, (byte)0x17, (byte)0x05, 
            (byte)0x2B, (byte)0xAA, (byte)0x75, (byte)0x98, 
            (byte)0xFE, (byte)0x3E, (byte)0x4F, (byte)0x4F, 
            (byte)0xC5, (byte)0xC5, (byte)0xF6, (byte)0x16, 
            (byte)0xE1, (byte)0x22, (byte)0xCF, (byte)0xF9, 
            (byte)0xEB, (byte)0xD8, (byte)0x9E, (byte)0xF8, 
            (byte)0x1D, (byte)0xC7, (byte)0xCE, (byte)0x8B, 
            (byte)0xF5, (byte)0x6C, (byte)0xC6, (byte)0x4B, 
            (byte)0x43, (byte)0x58, (byte)0x6C, (byte)0x80, 
            (byte)0xF1, (byte)0xC4, (byte)0xF5, (byte)0x6D, 
            (byte)0xD5, (byte)0x71, (byte)0x8F, (byte)0xDD, 
            (byte)0x76, (byte)0x30, (byte)0x0B, (byte)0xE3, 
            (byte)0x36, (byte)0x78, (byte)0x42, (byte)0x59, 
            (byte)0xCA, (byte)0x25, (byte)0xAA, (byte)0xDE, 
            (byte)0x5A, (byte)0x48, (byte)0x3F, (byte)0x64, 
            (byte)0xC0, (byte)0x2A, (byte)0x20, (byte)0xCF, 
            (byte)0x4A, (byte)0x10, (byte)0xF9, (byte)0xC1, 
            (byte)0x89, (byte)0xC4, (byte)0x33, (byte)0xDE, 
            (byte)0xFE, (byte)0x31, (byte)0xD2, (byte)0x63, 
            (byte)0xE6, (byte)0xC9, (byte)0x76, (byte)0x46,
            (byte)0x60, (byte)0xA7, (byte)0x31, (byte)0xEC, 
            (byte)0xCA, (byte)0xEC, (byte)0xB7, (byte)0x4C, 
            (byte)0x82, (byte)0x79, (byte)0x30, (byte)0x37, 
            (byte)0x31, (byte)0xE8, (byte)0xCF, (byte)0x69, 
            (byte)0x20, (byte)0x5B, (byte)0xC7, (byte)0x3E, 
            (byte)0x5A, (byte)0x70, (byte)0xBD, (byte)0xF9, 
            (byte)0x3E, (byte)0x5B, (byte)0xB6, (byte)0x81, 
            (byte)0xDA, (byte)0xB4, (byte)0xEE, (byte)0xB9,
            (byte)0xC7, (byte)0x33, (byte)0xCA, (byte)0xAB, 
            (byte)0x2F, (byte)0x67, (byte)0x3C, (byte)0x47, 
            (byte)0x5E, (byte)0x0E, (byte)0xCA, (byte)0x92, 
            (byte)0x1D, (byte)0x29, (byte)0x78, (byte)0x2E    
        }); 
	    public static readonly Math.BigInteger Keyx1024C_94_C = new Math.BigInteger(1, new byte[] {
            (byte)0x93, (byte)0xF8, (byte)0x28, (byte)0xD3    
        }); 
	    public static readonly Math.BigInteger Keyx1024C_94_D = new Math.BigInteger(1, new byte[] {
            (byte)0xCA, (byte)0x82, (byte)0xCC, (byte)0xE7, 
            (byte)0x8A, (byte)0x73, (byte)0x8B, (byte)0xC4, 
            (byte)0x6F, (byte)0x10, (byte)0x3D, (byte)0x53, 
            (byte)0xB9, (byte)0xBF, (byte)0x80, (byte)0x97, 
            (byte)0x45, (byte)0xEC, (byte)0x84, (byte)0x5E, 
            (byte)0x4F, (byte)0x6D, (byte)0xA4, (byte)0x62, 
            (byte)0x60, (byte)0x6C, (byte)0x51, (byte)0xF6, 
            (byte)0x0E, (byte)0xCF, (byte)0x30, (byte)0x2E, 
            (byte)0x31, (byte)0x20, (byte)0x4B, (byte)0x81    
        }); 
        public static readonly ASN1.ISO.AlgorithmIdentifier Keyx1024C_94_VP = new ASN1.ISO.AlgorithmIdentifier(
            new ObjectIdentifier(OID.gostR3410_1994_bBis), new GOSTR3410ValidationParameters(
                new Integer(371898640), new Integer(Keyx1024C_94_C), new Integer(Keyx1024C_94_D)
        )); 
	    // таблица именованных параметров
	    private static readonly Dictionary<String, GOSTR3410ParamSet1994> set = 
		    new Dictionary<String, GOSTR3410ParamSet1994>(); 
	    static GOSTR3410ParamSet1994()
        {
		    set.Add(OID.signs_test, new GOSTR3410ParamSet1994(
			    new Integer(Sign512T_94_T), new Integer(Sign512T_94_P), 
                new Integer(Sign512T_94_Q), new Integer(Sign512T_94_A), Sign512T_94_VP
		    )); 
		    set.Add(OID.signs_A, new GOSTR3410ParamSet1994(
			    new Integer(Sign1024A_94_T), new Integer(Sign1024A_94_P), 
                new Integer(Sign1024A_94_Q), new Integer(Sign1024A_94_A), Sign1024A_94_VP
		    )); 
		    set.Add(OID.signs_B, new GOSTR3410ParamSet1994(
			    new Integer(Sign1024B_94_T), new Integer(Sign1024B_94_P), 
                new Integer(Sign1024B_94_Q), new Integer(Sign1024B_94_A), Sign1024B_94_VP
		    )); 
		    set.Add(OID.signs_C, new GOSTR3410ParamSet1994(
			    new Integer(Sign1024C_94_T), new Integer(Sign1024C_94_P), 
                new Integer(Sign1024C_94_Q), new Integer(Sign1024C_94_A), Sign1024C_94_VP
		    )); 
		    set.Add(OID.signs_D, new GOSTR3410ParamSet1994(
			    new Integer(Sign1024D_94_T), new Integer(Sign1024D_94_P), 
                new Integer(Sign1024D_94_Q), new Integer(Sign1024D_94_A), Sign1024D_94_VP
		    )); 
		    set.Add(OID.exchanges_A, new GOSTR3410ParamSet1994(
			    new Integer(Keyx1024A_94_T), new Integer(Keyx1024A_94_P), 
                new Integer(Keyx1024A_94_Q), new Integer(Keyx1024A_94_A), Keyx1024A_94_VP
		    )); 
		    set.Add(OID.exchanges_B, new GOSTR3410ParamSet1994(
			    new Integer(Keyx1024B_94_T), new Integer(Keyx1024B_94_P), 
                new Integer(Keyx1024B_94_Q), new Integer(Keyx1024B_94_A), Keyx1024B_94_VP
		    )); 
		    set.Add(OID.exchanges_C, new GOSTR3410ParamSet1994(
			    new Integer(Keyx1024C_94_T), new Integer(Keyx1024C_94_P), 
                new Integer(Keyx1024C_94_Q), new Integer(Keyx1024C_94_A), Keyx1024C_94_VP
		    )); 
	    }
	    // получить именованные параметры
	    public static GOSTR3410ParamSet1994 Parameters(string oid) { return set[oid]; } 
    }
}
