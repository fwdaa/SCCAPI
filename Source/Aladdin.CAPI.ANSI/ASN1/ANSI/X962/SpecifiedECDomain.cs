using System; 
using System.IO; 
using System.Collections.Generic; 
using System.Runtime.Serialization;

namespace Aladdin.ASN1.ANSI.X962
{
    ////////////////////////////////////////////////////////////////////////////////
    // ECPVer ::= INTEGER {ecdpVer1(1), ecdpVer1(2), ecdpVer1(3)}
    // ECPoint ::= OCTET STRING
    // ECParameters ::= SEQUENCE {
    //      version ECPVer,
    //      fieldID FieldID,
    //      curve Curve,
    //      base ECPoint,
    //      order INTEGER,
    //      cofactor INTEGER OPTIONAL, 
    //      hash AlgorithmIdentifier OPTIONAL 
    // }
    ////////////////////////////////////////////////////////////////////////////////
	[Serializable]
    public class SpecifiedECDomain : Sequence
    {
	    // информация о структуре
	    private static readonly ObjectInfo[] info = new ObjectInfo[] { 
        
		    new ObjectInfo(new ObjectCreator<Integer                >().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<FieldID                >().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Curve                  >().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<OctetString            >().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer                >().Factory(), Cast.N), 
		    new ObjectInfo(new ObjectCreator<Integer                >().Factory(), Cast.O), 
		    new ObjectInfo(new ObjectCreator<ISO.AlgorithmIdentifier>().Factory(), Cast.O) 
	    }; 
		// конструктор при сериализации
        protected SpecifiedECDomain(SerializationInfo info, StreamingContext context) : base(info, context) {}

	    // конструктор при раскодировании
	    public SpecifiedECDomain(IEncodable encodable) : base(encodable, info) 
        {
            // проверить корректность данных
            if (Curve.Seed == null && Version.Value.IntValue > 1) throw new InvalidDataException(); 
        }
	    // конструктор при закодировании
	    public SpecifiedECDomain(Integer version, FieldID fieldID, Curve curve, 
            OctetString generator, Integer order, Integer cofactor, ISO.AlgorithmIdentifier hash)
		    : base(info, version, fieldID, curve, generator, order, cofactor, hash) 
        {
            if (Curve.Seed == null && Version.Value.IntValue > 1) throw new ArgumentException(); 
        } 
	    public Integer                  Version   { get { return (Integer                )this[0]; }}
	    public FieldID                  FieldID   { get { return (FieldID                )this[1]; }} 
	    public Curve                    Curve     { get { return (Curve                  )this[2]; }}
	    public OctetString              Generator { get { return (OctetString            )this[3]; }} 
	    public Integer                  Order     { get { return (Integer                )this[4]; }} 
	    public Integer                  Cofactor  { get { return (Integer                )this[5]; }} 
	    public ISO.AlgorithmIdentifier  Hash      { get { return (ISO.AlgorithmIdentifier)this[6]; }} 

        ////////////////////////////////////////////////////////////////////////////
        // Наборы c2pnb163v1, c2pnb163v2, c2pnb163v3
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2PNB163 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(163), 
                new ObjectIdentifier(OID.x962_c2_basis_pp), 
                new Pentanomial(new Integer(1), new Integer(2), new Integer(8))
            )
        );
        private static readonly Curve CurveC2PNB163V1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x07, (byte)0x25, (byte)0x46, (byte)0xB5, 
                (byte)0x43, (byte)0x52, (byte)0x34, (byte)0xA4, 
                (byte)0x22, (byte)0xE0, (byte)0x78, (byte)0x96, 
                (byte)0x75, (byte)0xF4, (byte)0x32, (byte)0xC8, 
                (byte)0x94, (byte)0x35, (byte)0xDE, (byte)0x52, 
                (byte)0x42
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0xC9, (byte)0x51, (byte)0x7D, 
                (byte)0x06, (byte)0xD5, (byte)0x24, (byte)0x0D, 
                (byte)0x3C, (byte)0xFF, (byte)0x38, (byte)0xC7, 
                (byte)0x4B, (byte)0x20, (byte)0xB6, (byte)0xCD, 
                (byte)0x4D, (byte)0x6F, (byte)0x9D, (byte)0xD4, 
                (byte)0xD9
            }), new BitString(new byte[] {
                (byte)0xD2, (byte)0xC0, (byte)0xFB, (byte)0x15, 
                (byte)0x76, (byte)0x08, (byte)0x60, (byte)0xDE, 
                (byte)0xF1, (byte)0xEE, (byte)0xF4, (byte)0xD6, 
                (byte)0x96, (byte)0xE6, (byte)0x76, (byte)0x87, 
                (byte)0x56, (byte)0x15, (byte)0x17, (byte)0x54
            })
        ); 
        private static readonly SpecifiedECDomain ECC2PNB163V1 = new SpecifiedECDomain(
            new Integer(1), FieldC2PNB163, CurveC2PNB163V1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x07, (byte)0xAF, (byte)0x69, (byte)0x98, 
                (byte)0x95, (byte)0x46, (byte)0x10, (byte)0x3D, (byte)0x79, 
                (byte)0x32, (byte)0x9F, (byte)0xCC, (byte)0x3D, (byte)0x74, 
                (byte)0x88, (byte)0x0F, (byte)0x33, (byte)0xBB, (byte)0xE8, 
                (byte)0x03, (byte)0xCB
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x01, (byte)0xE6, (byte)0x0F, (byte)0xC8, (byte)0x82, 
                (byte)0x1C, (byte)0xC7, (byte)0x4D, (byte)0xAE, (byte)0xAF, 
                (byte)0xC1
            })), new Integer(0x02), null
        ); 
        private static readonly Curve CurveC2PNB163V2 = new Curve(
            new OctetString(new byte[] {
                (byte)0x01, (byte)0x08, (byte)0xB3, (byte)0x9E, 
                (byte)0x77, (byte)0xC4, (byte)0xB1, (byte)0x08, 
                (byte)0xBE, (byte)0xD9, (byte)0x81, (byte)0xED, 
                (byte)0x0E, (byte)0x89, (byte)0x0E, (byte)0x11, 
                (byte)0x7C, (byte)0x51, (byte)0x1C, (byte)0xF0, 
                (byte)0x72
            }), new OctetString(new byte[] {
                (byte)0x06, (byte)0x67, (byte)0xAC, (byte)0xEB, 
                (byte)0x38, (byte)0xAF, (byte)0x4E, (byte)0x48, 
                (byte)0x8C, (byte)0x40, (byte)0x74, (byte)0x33, 
                (byte)0xFF, (byte)0xAE, (byte)0x4F, (byte)0x1C, 
                (byte)0x81, (byte)0x16, (byte)0x38, (byte)0xDF, 
                (byte)0x20 
            }), new BitString(new byte[] {
                (byte)0x53, (byte)0x81, (byte)0x4C, (byte)0x05, 
                (byte)0x0D, (byte)0x44, (byte)0xD6, (byte)0x96, 
                (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
                (byte)0x15, (byte)0x17, (byte)0x58, (byte)0x0C, 
                (byte)0xA4, (byte)0xE2, (byte)0x9F, (byte)0xFD
            })
        ); 
        private static readonly SpecifiedECDomain ECC2PNB163V2 = new SpecifiedECDomain(
            new Integer(1), FieldC2PNB163, CurveC2PNB163V2, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x00, (byte)0x24, (byte)0x26, 
                (byte)0x6E, (byte)0x4E, (byte)0xB5, (byte)0x10, 
                (byte)0x6D, (byte)0x0A, (byte)0x96, (byte)0x4D, 
                (byte)0x92, (byte)0xC4, (byte)0x86, (byte)0x0E, 
                (byte)0x26, (byte)0x71, (byte)0xDB, (byte)0x9B, 
                (byte)0x6C, (byte)0xC5
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x03, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFD, (byte)0xF6, 
                (byte)0x4D, (byte)0xE1, (byte)0x15, (byte)0x1A, 
                (byte)0xDB, (byte)0xB7, (byte)0x8F, (byte)0x10, 
                (byte)0xA7
            })), new Integer(0x02), null
        ); 
        private static readonly Curve CurveC2PNB163V3 = new Curve(
            new OctetString(new byte[] {
                (byte)0x07, (byte)0xA5, (byte)0x26, (byte)0xC6, 
                (byte)0x3D, (byte)0x3E, (byte)0x25, (byte)0xA2, 
                (byte)0x56, (byte)0xA0, (byte)0x07, (byte)0x69, 
                (byte)0x9F, (byte)0x54, (byte)0x47, (byte)0xE3, 
                (byte)0x2A, (byte)0xE4, (byte)0x56, (byte)0xB5, 
                (byte)0x0E
            }), new OctetString(new byte[] {
                (byte)0x03, (byte)0xF7, (byte)0x06, (byte)0x17, 
                (byte)0x98, (byte)0xEB, (byte)0x99, (byte)0xE2, 
                (byte)0x38, (byte)0xFD, (byte)0x6F, (byte)0x1B, 
                (byte)0xF9, (byte)0x5B, (byte)0x48, (byte)0xFE, 
                (byte)0xEB, (byte)0x48, (byte)0x54, (byte)0x25, 
                (byte)0x2B
            }), new BitString(new byte[] {
                (byte)0x50, (byte)0xCB, (byte)0xF1, (byte)0xD9, 
                (byte)0x5C, (byte)0xA9, (byte)0x4D, (byte)0x69, 
                (byte)0x6E, (byte)0x67, (byte)0x68, (byte)0x75, 
                (byte)0x61, (byte)0x51, (byte)0x75, (byte)0xF1, 
                (byte)0x6A, (byte)0x36, (byte)0xA3, (byte)0xB8
            })
        ); 
        private static readonly SpecifiedECDomain ECC2PNB163V3 = new SpecifiedECDomain(
            new Integer(1), FieldC2PNB163, CurveC2PNB163V3, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x02, (byte)0xF9, (byte)0xF8, 
                (byte)0x7B, (byte)0x7C, (byte)0x57, (byte)0x4D, 
                (byte)0x0B, (byte)0xDE, (byte)0xCF, (byte)0x8A, 
                (byte)0x22, (byte)0xE6, (byte)0x52, (byte)0x47, 
                (byte)0x75, (byte)0xF9, (byte)0x8C, (byte)0xDE, 
                (byte)0xBD, (byte)0xCB
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x03, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFE, (byte)0x1A, 
                (byte)0xEE, (byte)0x14, (byte)0x0F, (byte)0x11, 
                (byte)0x0A, (byte)0xFF, (byte)0x96, (byte)0x13, 
                (byte)0x09
            })), new Integer(0x02), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор c2pnb176w1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2PNB176 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(176), 
                new ObjectIdentifier(OID.x962_c2_basis_pp), 
                new Pentanomial(new Integer(1), new Integer(2), new Integer(43))
            )
        );
        private static readonly Curve CurveC2PNB176W1 = new Curve(
            new OctetString(new byte[] {
                (byte)0xE4, (byte)0xE6, (byte)0xDB, (byte)0x29, 
                (byte)0x95, (byte)0x06, (byte)0x5C, (byte)0x40, 
                (byte)0x7D, (byte)0x9D, (byte)0x39, (byte)0xB8, 
                (byte)0xD0, (byte)0x96, (byte)0x7B, (byte)0x96, 
                (byte)0x70, (byte)0x4B, (byte)0xA8, (byte)0xE9, 
                (byte)0xC9, (byte)0x0B
            }), new OctetString(new byte[] {
                (byte)0x5D, (byte)0xDA, (byte)0x47, (byte)0x0A, 
                (byte)0xBE, (byte)0x64, (byte)0x14, (byte)0xDE, 
                (byte)0x8E, (byte)0xC1, (byte)0x33, (byte)0xAE, 
                (byte)0x28, (byte)0xE9, (byte)0xBB, (byte)0xD7, 
                (byte)0xFC, (byte)0xEC, (byte)0x0A, (byte)0xE0, 
                (byte)0xFF, (byte)0xF2
            }), null
        ); 
        private static readonly SpecifiedECDomain ECC2PNB176W1 = new SpecifiedECDomain(
            new Integer(1), FieldC2PNB176, CurveC2PNB176W1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x8D, (byte)0x16, (byte)0xC2, 
                (byte)0x86, (byte)0x67, (byte)0x98, (byte)0xB6, 
                (byte)0x00, (byte)0xF9, (byte)0xF0, (byte)0x8B, 
                (byte)0xB4, (byte)0xA8, (byte)0xE8, (byte)0x60, 
                (byte)0xF3, (byte)0x29, (byte)0x8C, (byte)0xE0, 
                (byte)0x4A, (byte)0x57, (byte)0x98
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x92, (byte)0x53, 
                (byte)0x73, (byte)0x97, (byte)0xEC, (byte)0xA4, 
                (byte)0xF6, (byte)0x14, (byte)0x57, (byte)0x99, 
                (byte)0xD6, (byte)0x2B, (byte)0x0A, (byte)0x19, 
                (byte)0xCE, (byte)0x06, (byte)0xFE, (byte)0x26, 
                (byte)0xAD
            })), new Integer(0xFF6E), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы c2tnb191v1, c2tnb191v2, c2tnb191v3
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2TNB191 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(191), 
                new ObjectIdentifier(OID.x962_c2_basis_tp), 
                new Integer(9)
            )
        );
        private static readonly Curve CurveC2TNB191V1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x28, (byte)0x66, (byte)0x53, (byte)0x7B, 
                (byte)0x67, (byte)0x67, (byte)0x52, (byte)0x63, 
                (byte)0x6A, (byte)0x68, (byte)0xF5, (byte)0x65, 
                (byte)0x54, (byte)0xE1, (byte)0x26, (byte)0x40, 
                (byte)0x27, (byte)0x6B, (byte)0x64, (byte)0x9E, 
                (byte)0xF7, (byte)0x52, (byte)0x62, (byte)0x67
            }), new OctetString(new byte[] {
                (byte)0x2E, (byte)0x45, (byte)0xEF, (byte)0x57, 
                (byte)0x1F, (byte)0x00, (byte)0x78, (byte)0x6F, 
                (byte)0x67, (byte)0xB0, (byte)0x08, (byte)0x1B, 
                (byte)0x94, (byte)0x95, (byte)0xA3, (byte)0xD9, 
                (byte)0x54, (byte)0x62, (byte)0xF5, (byte)0xDE, 
                (byte)0x0A, (byte)0xA1, (byte)0x85, (byte)0xEC
            }), new BitString(new byte[] {
                (byte)0x4E, (byte)0x13, (byte)0xCA, (byte)0x54, 
                (byte)0x27, (byte)0x44, (byte)0xD6, (byte)0x96, 
                (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
                (byte)0x15, (byte)0x17, (byte)0x55, (byte)0x2F, 
                (byte)0x27, (byte)0x9A, (byte)0x8C, (byte)0x84
            })
        ); 
        private static readonly SpecifiedECDomain ECC2TNB191V1 = new SpecifiedECDomain(
            new Integer(1), FieldC2TNB191, CurveC2TNB191V1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x36, (byte)0xB3, (byte)0xDA, 
                (byte)0xF8, (byte)0xA2, (byte)0x32, (byte)0x06, 
                (byte)0xF9, (byte)0xC4, (byte)0xF2, (byte)0x99, 
                (byte)0xD7, (byte)0xB2, (byte)0x1A, (byte)0x9C, 
                (byte)0x36, (byte)0x91, (byte)0x37, (byte)0xF2, 
                (byte)0xC8, (byte)0x4A, (byte)0xE1, (byte)0xAA, 
                (byte)0x0D
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x40, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x04, (byte)0xA2, (byte)0x0E, (byte)0x90, 
                (byte)0xC3, (byte)0x90, (byte)0x67, (byte)0xC8, 
                (byte)0x93, (byte)0xBB, (byte)0xB9, (byte)0xA5
            })), new Integer(0x02), null
        ); 
        private static readonly Curve CurveC2TNB191V2 = new Curve(
            new OctetString(new byte[] {
                (byte)0x40, (byte)0x10, (byte)0x28, (byte)0x77, 
                (byte)0x4D, (byte)0x77, (byte)0x77, (byte)0xC7, 
                (byte)0xB7, (byte)0x66, (byte)0x6D, (byte)0x13, 
                (byte)0x66, (byte)0xEA, (byte)0x43, (byte)0x20, 
                (byte)0x71, (byte)0x27, (byte)0x4F, (byte)0x89, 
                (byte)0xFF, (byte)0x01, (byte)0xE7, (byte)0x18
            }), new OctetString(new byte[] {
                (byte)0x06, (byte)0x20, (byte)0x04, (byte)0x8D, 
                (byte)0x28, (byte)0xBC, (byte)0xBD, (byte)0x03, 
                (byte)0xB6, (byte)0x24, (byte)0x9C, (byte)0x99, 
                (byte)0x18, (byte)0x2B, (byte)0x7C, (byte)0x8C, 
                (byte)0xD1, (byte)0x97, (byte)0x00, (byte)0xC3, 
                (byte)0x62, (byte)0xC4, (byte)0x6A, (byte)0x01
            }), new BitString(new byte[] {
                (byte)0x08, (byte)0x71, (byte)0xEF, (byte)0x2F, 
                (byte)0xEF, (byte)0x24, (byte)0xD6, (byte)0x96, 
                (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
                (byte)0x15, (byte)0x17, (byte)0x58, (byte)0xBE, 
                (byte)0xE0, (byte)0xD9, (byte)0x5C, (byte)0x15        
            })
        ); 
        private static readonly SpecifiedECDomain ECC2TNB191V2 = new SpecifiedECDomain(
            new Integer(1), FieldC2TNB191, CurveC2TNB191V2, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x38, (byte)0x09, (byte)0xB2, 
                (byte)0xB7, (byte)0xCC, (byte)0x1B, (byte)0x28, 
                (byte)0xCC, (byte)0x5A, (byte)0x87, (byte)0x92, 
                (byte)0x6A, (byte)0xAD, (byte)0x83, (byte)0xFD, 
                (byte)0x28, (byte)0x78, (byte)0x9E, (byte)0x81, 
                (byte)0xE2, (byte)0xC9, (byte)0xE3, (byte)0xBF, 
                (byte)0x10        
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x50, (byte)0x50, (byte)0x8C, (byte)0xB8, 
                (byte)0x9F, (byte)0x65, (byte)0x28, (byte)0x24, 
                (byte)0xE0, (byte)0x6B, (byte)0x81, (byte)0x73
            })), new Integer(0x04), null
        ); 
        private static readonly Curve CurveC2TNB191V3 = new Curve(
            new OctetString(new byte[] {
                (byte)0x6C, (byte)0x01, (byte)0x07, (byte)0x47, 
                (byte)0x56, (byte)0x09, (byte)0x91, (byte)0x22, 
                (byte)0x22, (byte)0x10, (byte)0x56, (byte)0x91, 
                (byte)0x1C, (byte)0x77, (byte)0xD7, (byte)0x7E, 
                (byte)0x77, (byte)0xA7, (byte)0x77, (byte)0xE7, 
                (byte)0xE7, (byte)0xE7, (byte)0x7F, (byte)0xCB
            }), new OctetString(new byte[] {
                (byte)0x71, (byte)0xFE, (byte)0x1A, (byte)0xF9, 
                (byte)0x26, (byte)0xCF, (byte)0x84, (byte)0x79, 
                (byte)0x89, (byte)0xEF, (byte)0xEF, (byte)0x8D, 
                (byte)0xB4, (byte)0x59, (byte)0xF6, (byte)0x63, 
                (byte)0x94, (byte)0xD9, (byte)0x0F, (byte)0x32, 
                (byte)0xAD, (byte)0x3F, (byte)0x15, (byte)0xE8
            }), new BitString(new byte[] {
                (byte)0xE0, (byte)0x53, (byte)0x51, (byte)0x2D, 
                (byte)0xC6, (byte)0x84, (byte)0xD6, (byte)0x96, 
                (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
                (byte)0x15, (byte)0x17, (byte)0x50, (byte)0x67, 
                (byte)0xAE, (byte)0x78, (byte)0x6D, (byte)0x1F        
            })
        ); 
        private static readonly SpecifiedECDomain ECC2TNB191V3 = new SpecifiedECDomain(
            new Integer(1), FieldC2TNB191, CurveC2TNB191V3, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x37, (byte)0x5D, (byte)0x4C, 
                (byte)0xE2, (byte)0x4F, (byte)0xDE, (byte)0x43, 
                (byte)0x44, (byte)0x89, (byte)0xDE, (byte)0x87, 
                (byte)0x46, (byte)0xE7, (byte)0x17, (byte)0x86, 
                (byte)0x01, (byte)0x50, (byte)0x09, (byte)0xE6, 
                (byte)0x6E, (byte)0x38, (byte)0xA9, (byte)0x26, 
                (byte)0xDD
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x15, (byte)0x55, (byte)0x55, (byte)0x55, 
                (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
                (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
                (byte)0x61, (byte)0x0C, (byte)0x0B, (byte)0x19, 
                (byte)0x68, (byte)0x12, (byte)0xBF, (byte)0xB6, 
                (byte)0x28, (byte)0x8A, (byte)0x3E, (byte)0xA3
            })), new Integer(0x06), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы c2onb191v4, c2onb191v5
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2ONB191 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(191), 
                new ObjectIdentifier(OID.x962_c2_basis_gn), 
                Null.Instance
            )
        );
        private static readonly Curve CurveC2ONB191V4 = new Curve(
            new OctetString(new byte[] {
                (byte)0x65, (byte)0x90, (byte)0x3E, (byte)0x04, 
                (byte)0xE1, (byte)0xE4, (byte)0x92, (byte)0x42, 
                (byte)0x53, (byte)0xE2, (byte)0x6A, (byte)0x3C, 
                (byte)0x9A, (byte)0xC2, (byte)0x8C, (byte)0x75, 
                (byte)0x8B, (byte)0xD8, (byte)0x18, (byte)0x4A, 
                (byte)0x3F, (byte)0xB6, (byte)0x80, (byte)0xE8
            }), new OctetString(new byte[] {
                (byte)0x54, (byte)0x67, (byte)0x86, (byte)0x21, 
                (byte)0xB1, (byte)0x90, (byte)0xCF, (byte)0xCE, 
                (byte)0x28, (byte)0x2A, (byte)0xDE, (byte)0x21, 
                (byte)0x9D, (byte)0x5B, (byte)0x3A, (byte)0x06, 
                (byte)0x5E, (byte)0x3F, (byte)0x4B, (byte)0x3F, 
                (byte)0xFD, (byte)0xEB, (byte)0xB2, (byte)0x9B
            }), new BitString(new byte[] {
                (byte)0xA3, (byte)0x99, (byte)0x38, (byte)0x7E, 
                (byte)0xAE, (byte)0x54, (byte)0xD6, (byte)0x96, 
                (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
                (byte)0x15, (byte)0x17, (byte)0x50, (byte)0xE5, 
                (byte)0x8B, (byte)0x41, (byte)0x6D, (byte)0x57
            })
        ); 
        private static readonly SpecifiedECDomain ECC2ONB191V4 = new SpecifiedECDomain(
            new Integer(1), FieldC2ONB191, CurveC2ONB191V4, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x5A, (byte)0x2C, (byte)0x69, 
                (byte)0xA3, (byte)0x2E, (byte)0x86, (byte)0x38, 
                (byte)0xE5, (byte)0x1C, (byte)0xCE, (byte)0xFA, 
                (byte)0xAD, (byte)0x05, (byte)0x35, (byte)0x0A, 
                (byte)0x97, (byte)0x84, (byte)0x57, (byte)0xCB, 
                (byte)0x5F, (byte)0xB6, (byte)0xDF, (byte)0x99, 
                (byte)0x4A
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x40, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x9C, (byte)0xF2, (byte)0xD6, (byte)0xE3, 
                (byte)0x90, (byte)0x1D, (byte)0xAC, (byte)0x4C, 
                (byte)0x32, (byte)0xEE, (byte)0xC6, (byte)0x5D
            })), new Integer(0x02), null
        ); 
        private static readonly Curve CurveC2ONB191V5 = new Curve(
            new OctetString(new byte[] {
                (byte)0x25, (byte)0xF8, (byte)0xD0, (byte)0x6C, 
                (byte)0x97, (byte)0xC8, (byte)0x22, (byte)0x53, 
                (byte)0x6D, (byte)0x46, (byte)0x9C, (byte)0xD5, 
                (byte)0x17, (byte)0x0C, (byte)0xDD, (byte)0x7B, 
                (byte)0xB9, (byte)0xF5, (byte)0x00, (byte)0xBD, 
                (byte)0x6D, (byte)0xB1, (byte)0x10, (byte)0xFB
            }), new OctetString(new byte[] {
                (byte)0x75, (byte)0xFF, (byte)0x57, (byte)0x0E, 
                (byte)0x35, (byte)0xCA, (byte)0x94, (byte)0xFB, 
                (byte)0x37, (byte)0x80, (byte)0xC2, (byte)0x61, 
                (byte)0x9D, (byte)0x08, (byte)0x1C, (byte)0x17, 
                (byte)0xAA, (byte)0x59, (byte)0xFB, (byte)0xD5, 
                (byte)0xE5, (byte)0x91, (byte)0xC1, (byte)0xC4
            }), new BitString(new byte[] {
                (byte)0x2D, (byte)0x88, (byte)0xF7, (byte)0xBC, 
                (byte)0x54, (byte)0x57, (byte)0x94, (byte)0xD6, 
                (byte)0x96, (byte)0xE6, (byte)0x76, (byte)0x87, 
                (byte)0x56, (byte)0x15, (byte)0x17, (byte)0x59, 
                (byte)0x73, (byte)0x39, (byte)0x15, (byte)0x55        
            })
        ); 
        private static readonly SpecifiedECDomain ECC2ONB191V5 = new SpecifiedECDomain(
            new Integer(1), FieldC2ONB191, CurveC2ONB191V5, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x2A, (byte)0x16, (byte)0x91, 
                (byte)0x0E, (byte)0x8F, (byte)0x6C, (byte)0x4B, 
                (byte)0x19, (byte)0x9B, (byte)0xE2, (byte)0x42, 
                (byte)0x13, (byte)0x85, (byte)0x7A, (byte)0xBC, 
                (byte)0x9C, (byte)0x99, (byte)0x2E, (byte)0xDF, 
                (byte)0xB2, (byte)0x47, (byte)0x1F, (byte)0x3C, 
                (byte)0x68
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x0F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xEE, (byte)0xB3, (byte)0x54, (byte)0xB7, 
                (byte)0x27, (byte)0x0B, (byte)0x29, (byte)0x92, 
                (byte)0xB7, (byte)0x81, (byte)0x86, (byte)0x27
            })), new Integer(0x08), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор c2pnb208w1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2PNB208 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(208), 
                new ObjectIdentifier(OID.x962_c2_basis_pp), 
                new Pentanomial(new Integer(1), new Integer(2), new Integer(83))
            )
        );
        private static readonly Curve CurveC2PNB208W1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00
            }), new OctetString(new byte[] {
                (byte)0xC8, (byte)0x61, (byte)0x9E, (byte)0xD4, 
                (byte)0x5A, (byte)0x62, (byte)0xE6, (byte)0x21, 
                (byte)0x2E, (byte)0x11, (byte)0x60, (byte)0x34, 
                (byte)0x9E, (byte)0x2B, (byte)0xFA, (byte)0x84, 
                (byte)0x44, (byte)0x39, (byte)0xFA, (byte)0xFC, 
                (byte)0x2A, (byte)0x3F, (byte)0xD1, (byte)0x63, 
                (byte)0x8F, (byte)0x9E
            }), null
        ); 
        private static readonly SpecifiedECDomain ECC2PNB208W1 = new SpecifiedECDomain(
            new Integer(1), FieldC2PNB208, CurveC2PNB208W1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x89, (byte)0xFD, (byte)0xFB, 
                (byte)0xE4, (byte)0xAB, (byte)0xE1, (byte)0x93, 
                (byte)0xDF, (byte)0x95, (byte)0x59, (byte)0xEC, 
                (byte)0xF0, (byte)0x7A, (byte)0xC0, (byte)0xCE, 
                (byte)0x78, (byte)0x55, (byte)0x4E, (byte)0x27, 
                (byte)0x84, (byte)0xEB, (byte)0x8C, (byte)0x1E, 
                (byte)0xD1, (byte)0xA5, (byte)0x7A
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x01, (byte)0xBA, (byte)0xF9, 
                (byte)0x5C, (byte)0x97, (byte)0x23, (byte)0xC5, 
                (byte)0x7B, (byte)0x6C, (byte)0x21, (byte)0xDA, 
                (byte)0x2E, (byte)0xFF, (byte)0x2D, (byte)0x5E, 
                (byte)0xD5, (byte)0x88, (byte)0xBD, (byte)0xD5, 
                (byte)0x71, (byte)0x7E, (byte)0x21, (byte)0x2F, 
                (byte)0x9D
            })), new Integer(0xFE48), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы c2tnb239v1, c2tnb239v2, c2tnb239v3
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2TNB239 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(239), 
                new ObjectIdentifier(OID.x962_c2_basis_tp), 
                new Integer(36)
            )
        );
        private static readonly Curve CurveC2TNB239V1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x32, (byte)0x01, (byte)0x08, (byte)0x57, 
                (byte)0x07, (byte)0x7C, (byte)0x54, (byte)0x31, 
                (byte)0x12, (byte)0x3A, (byte)0x46, (byte)0xB8, 
                (byte)0x08, (byte)0x90, (byte)0x67, (byte)0x56, 
                (byte)0xF5, (byte)0x43, (byte)0x42, (byte)0x3E, 
                (byte)0x8D, (byte)0x27, (byte)0x87, (byte)0x75, 
                (byte)0x78, (byte)0x12, (byte)0x57, (byte)0x78, 
                (byte)0xAC, (byte)0x76        
            }), new OctetString(new byte[] {
                (byte)0x79, (byte)0x04, (byte)0x08, (byte)0xF2, 
                (byte)0xEE, (byte)0xDA, (byte)0xF3, (byte)0x92, 
                (byte)0xB0, (byte)0x12, (byte)0xED, (byte)0xEF, 
                (byte)0xB3, (byte)0x39, (byte)0x2F, (byte)0x30, 
                (byte)0xF4, (byte)0x32, (byte)0x7C, (byte)0x0C, 
                (byte)0xA3, (byte)0xF3, (byte)0x1F, (byte)0xC3, 
                (byte)0x83, (byte)0xC4, (byte)0x22, (byte)0xAA, 
                (byte)0x8C, (byte)0x16
            }), new BitString(new byte[] {
                (byte)0xD3, (byte)0x4B, (byte)0x9A, (byte)0x4D, 
                (byte)0x69, (byte)0x6E, (byte)0x67, (byte)0x68, 
                (byte)0x75, (byte)0x61, (byte)0x51, (byte)0x75, 
                (byte)0xCA, (byte)0x71, (byte)0xB9, (byte)0x20, 
                (byte)0xBF, (byte)0xEF, (byte)0xB0, (byte)0x5D
            })
        ); 
        private static readonly SpecifiedECDomain ECC2TNB239V1 = new SpecifiedECDomain(
            new Integer(1), FieldC2TNB239, CurveC2TNB239V1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x57, (byte)0x92, (byte)0x70, 
                (byte)0x98, (byte)0xFA, (byte)0x93, (byte)0x2E, 
                (byte)0x7C, (byte)0x0A, (byte)0x96, (byte)0xD3, 
                (byte)0xFD, (byte)0x5B, (byte)0x70, (byte)0x6E, 
                (byte)0xF7, (byte)0xE5, (byte)0xF5, (byte)0xC1, 
                (byte)0x56, (byte)0xE1, (byte)0x6B, (byte)0x7E, 
                (byte)0x7C, (byte)0x86, (byte)0x03, (byte)0x85, 
                (byte)0x52, (byte)0xE9, (byte)0x1D
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x0F, 
                (byte)0x4D, (byte)0x42, (byte)0xFF, (byte)0xE1, 
                (byte)0x49, (byte)0x2A, (byte)0x49, (byte)0x93, 
                (byte)0xF1, (byte)0xCA, (byte)0xD6, (byte)0x66, 
                (byte)0xE4, (byte)0x47
            })), new Integer(0x04), null
        ); 
        private static readonly Curve CurveC2TNB239V2 = new Curve(
            new OctetString(new byte[] {
                (byte)0x42, (byte)0x30, (byte)0x01, (byte)0x77, 
                (byte)0x57, (byte)0xA7, (byte)0x67, (byte)0xFA, 
                (byte)0xE4, (byte)0x23, (byte)0x98, (byte)0x56, 
                (byte)0x9B, (byte)0x74, (byte)0x63, (byte)0x25, 
                (byte)0xD4, (byte)0x53, (byte)0x13, (byte)0xAF, 
                (byte)0x07, (byte)0x66, (byte)0x26, (byte)0x64, 
                (byte)0x79, (byte)0xB7, (byte)0x56, (byte)0x54, 
                (byte)0xE6, (byte)0x5F
            }), new OctetString(new byte[] {
                (byte)0x50, (byte)0x37, (byte)0xEA, (byte)0x65, 
                (byte)0x41, (byte)0x96, (byte)0xCF, (byte)0xF0, 
                (byte)0xCD, (byte)0x82, (byte)0xB2, (byte)0xC1, 
                (byte)0x4A, (byte)0x2F, (byte)0xCF, (byte)0x2E, 
                (byte)0x3F, (byte)0xF8, (byte)0x77, (byte)0x52, 
                (byte)0x85, (byte)0xB5, (byte)0x45, (byte)0x72, 
                (byte)0x2F, (byte)0x03, (byte)0xEA, (byte)0xCD, 
                (byte)0xB7, (byte)0x4B
            }), new BitString(new byte[] {
                (byte)0x2A, (byte)0xA6, (byte)0x98, (byte)0x2F, 
                (byte)0xDF, (byte)0xA4, (byte)0xD6, (byte)0x96, 
                (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
                (byte)0x15, (byte)0x17, (byte)0x5D, (byte)0x26, 
                (byte)0x67, (byte)0x27, (byte)0x27, (byte)0x7D        
            })
        ); 
        private static readonly SpecifiedECDomain ECC2TNB239V2 = new SpecifiedECDomain(
            new Integer(1), FieldC2TNB239, CurveC2TNB239V2, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x28, (byte)0xF9, (byte)0xD0, 
                (byte)0x4E, (byte)0x90, (byte)0x00, (byte)0x69, 
                (byte)0xC8, (byte)0xDC, (byte)0x47, (byte)0xA0, 
                (byte)0x85, (byte)0x34, (byte)0xFE, (byte)0x76, 
                (byte)0xD2, (byte)0xB9, (byte)0x00, (byte)0xB7, 
                (byte)0xD7, (byte)0xEF, (byte)0x31, (byte)0xF5, 
                (byte)0x70, (byte)0x9F, (byte)0x20, (byte)0x0C, 
                (byte)0x4C, (byte)0xA2, (byte)0x05
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x15, (byte)0x55, (byte)0x55, (byte)0x55, 
                (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
                (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
                (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x3C, 
                (byte)0x6F, (byte)0x28, (byte)0x85, (byte)0x25, 
                (byte)0x9C, (byte)0x31, (byte)0xE3, (byte)0xFC, 
                (byte)0xDF, (byte)0x15, (byte)0x46, (byte)0x24, 
                (byte)0x52, (byte)0x2D
            })), new Integer(0x06), null
        ); 
        private static readonly Curve CurveC2TNB239V3 = new Curve(
            new OctetString(new byte[] {
                (byte)0x01, (byte)0x23, (byte)0x87, (byte)0x74, 
                (byte)0x66, (byte)0x6A, (byte)0x67, (byte)0x76, 
                (byte)0x6D, (byte)0x66, (byte)0x76, (byte)0xF7, 
                (byte)0x78, (byte)0xE6, (byte)0x76, (byte)0xB6, 
                (byte)0x69, (byte)0x99, (byte)0x17, (byte)0x66, 
                (byte)0x66, (byte)0xE6, (byte)0x87, (byte)0x66, 
                (byte)0x6D, (byte)0x87, (byte)0x66, (byte)0xC6, 
                (byte)0x6A, (byte)0x9F
            }), new OctetString(new byte[] {
                (byte)0x6A, (byte)0x94, (byte)0x19, (byte)0x77, 
                (byte)0xBA, (byte)0x9F, (byte)0x6A, (byte)0x43, 
                (byte)0x51, (byte)0x99, (byte)0xAC, (byte)0xFC, 
                (byte)0x51, (byte)0x06, (byte)0x7E, (byte)0xD5, 
                (byte)0x87, (byte)0xF5, (byte)0x19, (byte)0xC5, 
                (byte)0xEC, (byte)0xB5, (byte)0x41, (byte)0xB8, 
                (byte)0xE4, (byte)0x41, (byte)0x11, (byte)0xDE, 
                (byte)0x1D, (byte)0x40
            }), new BitString(new byte[] {
                (byte)0x9E, (byte)0x07, (byte)0x6F, (byte)0x4D, 
                (byte)0x69, (byte)0x6E, (byte)0x67, (byte)0x68, 
                (byte)0x75, (byte)0x61, (byte)0x51, (byte)0x75, 
                (byte)0xE1, (byte)0x1E, (byte)0x9F, (byte)0xDD, 
                (byte)0x77, (byte)0xF9, (byte)0x20, (byte)0x41
            })
        ); 
        private static readonly SpecifiedECDomain ECC2TNB239V3 = new SpecifiedECDomain(
            new Integer(1), FieldC2TNB239, CurveC2TNB239V3, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x70, (byte)0xF6, (byte)0xE9, 
                (byte)0xD0, (byte)0x4D, (byte)0x28, (byte)0x9C, 
                (byte)0x4E, (byte)0x89, (byte)0x91, (byte)0x3C, 
                (byte)0xE3, (byte)0x53, (byte)0x0B, (byte)0xFD, 
                (byte)0xE9, (byte)0x03, (byte)0x97, (byte)0x7D, 
                (byte)0x42, (byte)0xB1, (byte)0x46, (byte)0xD5, 
                (byte)0x39, (byte)0xBF, (byte)0x1B, (byte)0xDE, 
                (byte)0x4E, (byte)0x9C, (byte)0x92
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x0C, (byte)0xCC, (byte)0xCC, (byte)0xCC, 
                (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xCC, 
                (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xCC, 
                (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xAC, 
                (byte)0x49, (byte)0x12, (byte)0xD2, (byte)0xD9, 
                (byte)0xDF, (byte)0x90, (byte)0x3E, (byte)0xF9, 
                (byte)0x88, (byte)0x8B, (byte)0x8A, (byte)0x0E, 
                (byte)0x4C, (byte)0xFF        
            })), new Integer(0x0A), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы c2onb239v4, c2onb239v5
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2ONB239 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(239), 
                new ObjectIdentifier(OID.x962_c2_basis_gn), 
                Null.Instance
            )
        );
        private static readonly Curve CurveC2ONB239V4 = new Curve(
            new OctetString(new byte[] {
                (byte)0x18, (byte)0x2D, (byte)0xD4, (byte)0x5F, 
                (byte)0x5D, (byte)0x47, (byte)0x02, (byte)0x39, 
                (byte)0xB8, (byte)0x98, (byte)0x3F, (byte)0xEA, 
                (byte)0x47, (byte)0xB8, (byte)0xB2, (byte)0x92, 
                (byte)0x64, (byte)0x1C, (byte)0x57, (byte)0xF9, 
                (byte)0xBF, (byte)0x84, (byte)0xBA, (byte)0xEC, 
                (byte)0xDE, (byte)0x8B, (byte)0xB3, (byte)0xAD, 
                (byte)0xCE, (byte)0x30
            }), new OctetString(new byte[] {
                (byte)0x14, (byte)0x7A, (byte)0x9C, (byte)0x1D, 
                (byte)0x4C, (byte)0x2C, (byte)0xE9, (byte)0xBE, 
                (byte)0x5D, (byte)0x34, (byte)0xEC, (byte)0x02, 
                (byte)0x79, (byte)0x7F, (byte)0x76, (byte)0x66,
                (byte)0x7E, (byte)0xBA, (byte)0xD5, (byte)0xA3, 
                (byte)0xF9, (byte)0x3F, (byte)0xA2, (byte)0xA5, 
                (byte)0x24, (byte)0xBF, (byte)0xDE, (byte)0x91, 
                (byte)0xEF, (byte)0x28
            }), new BitString(new byte[] {
                (byte)0xF8, (byte)0x51, (byte)0x63, (byte)0x8C, 
                (byte)0xFA, (byte)0x4D, (byte)0x69, (byte)0x6E, 
                (byte)0x67, (byte)0x68, (byte)0x75, (byte)0x61, 
                (byte)0x51, (byte)0x75, (byte)0x56, (byte)0x51, 
                (byte)0x38, (byte)0x41, (byte)0xBF, (byte)0xAC
            })
        ); 
        private static readonly SpecifiedECDomain ECC2ONB239V4 = new SpecifiedECDomain(
            new Integer(1), FieldC2ONB239, CurveC2ONB239V4, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x49, (byte)0x12, (byte)0xAD, 
                (byte)0x65, (byte)0x7F, (byte)0x1D, (byte)0x1C, 
                (byte)0x6B, (byte)0x32, (byte)0xED, (byte)0xB9, 
                (byte)0x94, (byte)0x2C, (byte)0x95, (byte)0xE2, 
                (byte)0x26, (byte)0xB0, (byte)0x6F, (byte)0xB0, 
                (byte)0x12, (byte)0xCD, (byte)0x40, (byte)0xFD, 
                (byte)0xEA, (byte)0x0D, (byte)0x72, (byte)0x19, 
                (byte)0x7C, (byte)0x81, (byte)0x04
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x47, 
                (byte)0x4F, (byte)0x7E, (byte)0x69, (byte)0xF4, 
                (byte)0x2F, (byte)0xE4, (byte)0x30, (byte)0x93, 
                (byte)0x1D, (byte)0x0B, (byte)0x45, (byte)0x5A, 
                (byte)0xAE, (byte)0x8B
            })), new Integer(0x04), null
        ); 
        private static readonly Curve CurveC2ONB239V5 = new Curve(
            new OctetString(new byte[] {
                (byte)0x1E, (byte)0xCF, (byte)0x1B, (byte)0x9D, 
                (byte)0x28, (byte)0xD8, (byte)0x01, (byte)0x75, 
                (byte)0x05, (byte)0xE1, (byte)0x74, (byte)0x75, 
                (byte)0xD3, (byte)0xDF, (byte)0x29, (byte)0x82, 
                (byte)0xE2, (byte)0x43, (byte)0xCA, (byte)0x5C, 
                (byte)0xB5, (byte)0xE9, (byte)0xF9, (byte)0x4A, 
                (byte)0x3F, (byte)0x36, (byte)0x12, (byte)0x4A, 
                (byte)0x48, (byte)0x6E
            }), new OctetString(new byte[] {
                (byte)0x3E, (byte)0xE2, (byte)0x57, (byte)0x25, 
                (byte)0x0D, (byte)0x1A, (byte)0x2E, (byte)0x66, 
                (byte)0xCE, (byte)0xF2, (byte)0x3A, (byte)0xA0, 
                (byte)0xF2, (byte)0x5B, (byte)0x12, (byte)0x38, 
                (byte)0x8D, (byte)0xE8, (byte)0xA1, (byte)0x0F, 
                (byte)0xF9, (byte)0x55, (byte)0x4F, (byte)0x90, 
                (byte)0xAF, (byte)0xBA, (byte)0xA9, (byte)0xA0, 
                (byte)0x8B, (byte)0x6D
            }), new BitString(new byte[] {
                (byte)0x2C, (byte)0x04, (byte)0xF4, (byte)0x4D, 
                (byte)0x69, (byte)0x6E, (byte)0x67, (byte)0x68, 
                (byte)0x75, (byte)0x61, (byte)0x51, (byte)0x75, 
                (byte)0xC5, (byte)0x86, (byte)0xB4, (byte)0x1F, 
                (byte)0x6C, (byte)0xA1, (byte)0x50, (byte)0xC9
            })
        ); 
        private static readonly SpecifiedECDomain ECC2ONB239V5 = new SpecifiedECDomain(
            new Integer(1), FieldC2ONB239, CurveC2ONB239V5, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x19, (byte)0x32, (byte)0x79, 
                (byte)0xFC, (byte)0x54, (byte)0x3E, (byte)0x9F, 
                (byte)0x5F, (byte)0x71, (byte)0x19, (byte)0x18, 
                (byte)0x97, (byte)0x85, (byte)0xB9, (byte)0xC6, 
                (byte)0x0B, (byte)0x24, (byte)0x9B, (byte)0xE4, 
                (byte)0x82, (byte)0x0B, (byte)0xAF, (byte)0x6C, 
                (byte)0x24, (byte)0xBD, (byte)0xFA, (byte)0x28, 
                (byte)0x13, (byte)0xF8, (byte)0xB8
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x15, (byte)0x55, (byte)0x55, (byte)0x55, 
                (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
                (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x55, 
                (byte)0x55, (byte)0x55, (byte)0x55, (byte)0x8C, 
                (byte)0xF7, (byte)0x7A, (byte)0x5D, (byte)0x05, 
                (byte)0x89, (byte)0xD2, (byte)0xA9, (byte)0x34, 
                (byte)0x0D, (byte)0x96, (byte)0x3B, (byte)0x7A, 
                (byte)0xD7, (byte)0x03
            })), new Integer(0x06), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор c2pnb208w1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2PNB272 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(272), 
                new ObjectIdentifier(OID.x962_c2_basis_pp), 
                new Pentanomial(new Integer(1), new Integer(3), new Integer(56))
            )
        );
        private static readonly Curve CurveC2PNB272W1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x91, (byte)0xA0, (byte)0x91, (byte)0xF0, 
                (byte)0x3B, (byte)0x5F, (byte)0xBA, (byte)0x4A, 
                (byte)0xB2, (byte)0xCC, (byte)0xF4, (byte)0x9C, 
                (byte)0x4E, (byte)0xDD, (byte)0x22, (byte)0x0F, 
                (byte)0xB0, (byte)0x28, (byte)0x71, (byte)0x2D, 
                (byte)0x42, (byte)0xBE, (byte)0x75, (byte)0x2B, 
                (byte)0x2C, (byte)0x40, (byte)0x09, (byte)0x4D, 
                (byte)0xBA, (byte)0xCD, (byte)0xB5, (byte)0x86, 
                (byte)0xFB, (byte)0x20
            }), new OctetString(new byte[] {
                (byte)0x71, (byte)0x67, (byte)0xEF, (byte)0xC9, 
                (byte)0x2B, (byte)0xB2, (byte)0xE3, (byte)0xCE, 
                (byte)0x7C, (byte)0x8A, (byte)0xAA, (byte)0xFF, 
                (byte)0x34, (byte)0xE1, (byte)0x2A, (byte)0x9C, 
                (byte)0x55, (byte)0x70, (byte)0x03, (byte)0xD7, 
                (byte)0xC7, (byte)0x3A, (byte)0x6F, (byte)0xAF, 
                (byte)0x00, (byte)0x3F, (byte)0x99, (byte)0xF6, 
                (byte)0xCC, (byte)0x84, (byte)0x82, (byte)0xE5, 
                (byte)0x40, (byte)0xF7
            }), null
        ); 
        private static readonly SpecifiedECDomain ECC2PNB272W1 = new SpecifiedECDomain(
            new Integer(1), FieldC2PNB272, CurveC2PNB272W1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x61, (byte)0x08, (byte)0xBA, 
                (byte)0xBB, (byte)0x2C, (byte)0xEE, (byte)0xBC, 
                (byte)0xF7, (byte)0x87, (byte)0x05, (byte)0x8A, 
                (byte)0x05, (byte)0x6C, (byte)0xBE, (byte)0x0C, 
                (byte)0xFE, (byte)0x62, (byte)0x2D, (byte)0x77, 
                (byte)0x23, (byte)0xA2, (byte)0x89, (byte)0xE0, 
                (byte)0x8A, (byte)0x07, (byte)0xAE, (byte)0x13, 
                (byte)0xEF, (byte)0x0D, (byte)0x10, (byte)0xD1, 
                (byte)0x71, (byte)0xDD, (byte)0x8D
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0xFA, (byte)0xF5, 
                (byte)0x13, (byte)0x54, (byte)0xE0, (byte)0xE3, 
                (byte)0x9E, (byte)0x48, (byte)0x92, (byte)0xDF, 
                (byte)0x6E, (byte)0x31, (byte)0x9C, (byte)0x72, 
                (byte)0xC8, (byte)0x16, (byte)0x16, (byte)0x03, 
                (byte)0xFA, (byte)0x45, (byte)0xAA, (byte)0x7B, 
                (byte)0x99, (byte)0x8A, (byte)0x16, (byte)0x7B, 
                (byte)0x8F, (byte)0x1E, (byte)0x62, (byte)0x95, 
                (byte)0x21
            })), new Integer(0xFF06), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор c2pnb304w1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2PNB304 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(304), 
                new ObjectIdentifier(OID.x962_c2_basis_pp), 
                new Pentanomial(new Integer(1), new Integer(2), new Integer(11))
            )
        );
        private static readonly Curve CurveC2PNB304W1 = new Curve(
            new OctetString(new byte[] {
                (byte)0xFD, (byte)0x0D, (byte)0x69, (byte)0x31, 
                (byte)0x49, (byte)0xA1, (byte)0x18, (byte)0xF6, 
                (byte)0x51, (byte)0xE6, (byte)0xDC, (byte)0xE6, 
                (byte)0x80, (byte)0x20, (byte)0x85, (byte)0x37, 
                (byte)0x7E, (byte)0x5F, (byte)0x88, (byte)0x2D, 
                (byte)0x1B, (byte)0x51, (byte)0x0B, (byte)0x44, 
                (byte)0x16, (byte)0x00, (byte)0x74, (byte)0xC1, 
                (byte)0x28, (byte)0x80, (byte)0x78, (byte)0x36, 
                (byte)0x5A, (byte)0x03, (byte)0x96, (byte)0xC8, 
                (byte)0xE6, (byte)0x81
            }), new OctetString(new byte[] {
                (byte)0xBD, (byte)0xDB, (byte)0x97, (byte)0xE5, 
                (byte)0x55, (byte)0xA5, (byte)0x0A, (byte)0x90, 
                (byte)0x8E, (byte)0x43, (byte)0xB0, (byte)0x1C, 
                (byte)0x79, (byte)0x8E, (byte)0xA5, (byte)0xDA, 
                (byte)0xA6, (byte)0x78, (byte)0x8F, (byte)0x1E, 
                (byte)0xA2, (byte)0x79, (byte)0x4E, (byte)0xFC, 
                (byte)0xF5, (byte)0x71, (byte)0x66, (byte)0xB8, 
                (byte)0xC1, (byte)0x40, (byte)0x39, (byte)0x60, 
                (byte)0x1E, (byte)0x55, (byte)0x82, (byte)0x73, 
                (byte)0x40, (byte)0xBE
            }), null
        ); 
        private static readonly SpecifiedECDomain ECC2PNB304W1 = new SpecifiedECDomain(
            new Integer(1), FieldC2PNB304, CurveC2PNB304W1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x19, (byte)0x7B, (byte)0x07, 
                (byte)0x84, (byte)0x5E, (byte)0x9B, (byte)0xE2, 
                (byte)0xD9, (byte)0x6A, (byte)0xDB, (byte)0x0F, 
                (byte)0x5F, (byte)0x3C, (byte)0x7F, (byte)0x2C, 
                (byte)0xFF, (byte)0xBD, (byte)0x7A, (byte)0x3E, 
                (byte)0xB8, (byte)0xB6, (byte)0xFE, (byte)0xC3, 
                (byte)0x5C, (byte)0x7F, (byte)0xD6, (byte)0x7F, 
                (byte)0x26, (byte)0xDD, (byte)0xF6, (byte)0x28, 
                (byte)0x5A, (byte)0x64, (byte)0x4F, (byte)0x74, 
                (byte)0x0A, (byte)0x26, (byte)0x14
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x01, (byte)0xD5, (byte)0x56, 
                (byte)0x57, (byte)0x2A, (byte)0xAB, (byte)0xAC, 
                (byte)0x80, (byte)0x01, (byte)0x01, (byte)0xD5, 
                (byte)0x56, (byte)0x57, (byte)0x2A, (byte)0xAB, 
                (byte)0xAC, (byte)0x80, (byte)0x01, (byte)0x02, 
                (byte)0x2D, (byte)0x5C, (byte)0x91, (byte)0xDD, 
                (byte)0x17, (byte)0x3F, (byte)0x8F, (byte)0xB5, 
                (byte)0x61, (byte)0xDA, (byte)0x68, (byte)0x99, 
                (byte)0x16, (byte)0x44, (byte)0x43, (byte)0x05, 
                (byte)0x1D
            })), new Integer(0xFE2E), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор c2tnb359v1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2TNB359 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(359), 
                new ObjectIdentifier(OID.x962_c2_basis_tp), 
                new Integer(68)
            )
        );
        private static readonly Curve CurveC2TNB359V1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x56, (byte)0x67, (byte)0x67, (byte)0x6A, 
                (byte)0x65, (byte)0x4B, (byte)0x20, (byte)0x75, 
                (byte)0x4F, (byte)0x35, (byte)0x6E, (byte)0xA9, 
                (byte)0x20, (byte)0x17, (byte)0xD9, (byte)0x46, 
                (byte)0x56, (byte)0x7C, (byte)0x46, (byte)0x67, 
                (byte)0x55, (byte)0x56, (byte)0xF1, (byte)0x95, 
                (byte)0x56, (byte)0xA0, (byte)0x46, (byte)0x16, 
                (byte)0xB5, (byte)0x67, (byte)0xD2, (byte)0x23, 
                (byte)0xA5, (byte)0xE0, (byte)0x56, (byte)0x56, 
                (byte)0xFB, (byte)0x54, (byte)0x90, (byte)0x16, 
                (byte)0xA9, (byte)0x66, (byte)0x56, (byte)0xA5, 
                (byte)0x57
            }), new OctetString(new byte[] {
                (byte)0x24, (byte)0x72, (byte)0xE2, (byte)0xD0, 
                (byte)0x19, (byte)0x7C, (byte)0x49, (byte)0x36, 
                (byte)0x3F, (byte)0x1F, (byte)0xE7, (byte)0xF5, 
                (byte)0xB6, (byte)0xDB, (byte)0x07, (byte)0x5D, 
                (byte)0x52, (byte)0xB6, (byte)0x94, (byte)0x7D, 
                (byte)0x13, (byte)0x5D, (byte)0x8C, (byte)0xA4, 
                (byte)0x45, (byte)0x80, (byte)0x5D, (byte)0x39, 
                (byte)0xBC, (byte)0x34, (byte)0x56, (byte)0x26, 
                (byte)0x08, (byte)0x96, (byte)0x87, (byte)0x74, 
                (byte)0x2B, (byte)0x63, (byte)0x29, (byte)0xE7, 
                (byte)0x06, (byte)0x80, (byte)0x23, (byte)0x19, 
                (byte)0x88
            }), new BitString(new byte[] {
                (byte)0x2B, (byte)0x35, (byte)0x49, (byte)0x20, 
                (byte)0xB7, (byte)0x24, (byte)0xD6, (byte)0x96, 
                (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
                (byte)0x15, (byte)0x17, (byte)0x58, (byte)0x5B, 
                (byte)0xA1, (byte)0x33, (byte)0x2D, (byte)0xC6
            })
        ); 
        private static readonly SpecifiedECDomain ECC2TNB359V1 = new SpecifiedECDomain(
            new Integer(1), FieldC2TNB359, CurveC2TNB359V1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x3C, (byte)0x25, (byte)0x8E, 
                (byte)0xF3, (byte)0x04, (byte)0x77, (byte)0x67, 
                (byte)0xE7, (byte)0xED, (byte)0xE0, (byte)0xF1, 
                (byte)0xFD, (byte)0xAA, (byte)0x79, (byte)0xDA, 
                (byte)0xEE, (byte)0x38, (byte)0x41, (byte)0x36, 
                (byte)0x6A, (byte)0x13, (byte)0x2E, (byte)0x16, 
                (byte)0x3A, (byte)0xCE, (byte)0xD4, (byte)0xED, 
                (byte)0x24, (byte)0x01, (byte)0xDF, (byte)0x9C, 
                (byte)0x6B, (byte)0xDC, (byte)0xDE, (byte)0x98, 
                (byte)0xE8, (byte)0xE7, (byte)0x07, (byte)0xC0, 
                (byte)0x7A, (byte)0x22, (byte)0x39, (byte)0xB1, 
                (byte)0xB0, (byte)0x97
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0xAF, (byte)0x28, (byte)0x6B, 
                (byte)0xCA, (byte)0x1A, (byte)0xF2, (byte)0x86, 
                (byte)0xBC, (byte)0xA1, (byte)0xAF, (byte)0x28, 
                (byte)0x6B, (byte)0xCA, (byte)0x1A, (byte)0xF2, 
                (byte)0x86, (byte)0xBC, (byte)0xA1, (byte)0xAF, 
                (byte)0x28, (byte)0x6B, (byte)0xC9, (byte)0xFB, 
                (byte)0x8F, (byte)0x6B, (byte)0x85, (byte)0xC5, 
                (byte)0x56, (byte)0x89, (byte)0x2C, (byte)0x20, 
                (byte)0xA7, (byte)0xEB, (byte)0x96, (byte)0x4F, 
                (byte)0xE7, (byte)0x71, (byte)0x9E, (byte)0x74, 
                (byte)0xF4, (byte)0x90, (byte)0x75, (byte)0x8D, 
                (byte)0x3B
            })), new Integer(0x4C), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор c2pnb368w1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2PNB368 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(368), 
                new ObjectIdentifier(OID.x962_c2_basis_pp), 
                new Pentanomial(new Integer(1), new Integer(2), new Integer(85))
            )
        );
        private static readonly Curve CurveC2PNB368W1 = new Curve(
            new OctetString(new byte[] {
                (byte)0xE0, (byte)0xD2, (byte)0xEE, (byte)0x25, 
                (byte)0x09, (byte)0x52, (byte)0x06, (byte)0xF5, 
                (byte)0xE2, (byte)0xA4, (byte)0xF9, (byte)0xED, 
                (byte)0x22, (byte)0x9F, (byte)0x1F, (byte)0x25, 
                (byte)0x6E, (byte)0x79, (byte)0xA0, (byte)0xE2, 
                (byte)0xB4, (byte)0x55, (byte)0x97, (byte)0x0D, 
                (byte)0x8D, (byte)0x0D, (byte)0x86, (byte)0x5B, 
                (byte)0xD9, (byte)0x47, (byte)0x78, (byte)0xC5, 
                (byte)0x76, (byte)0xD6, (byte)0x2F, (byte)0x0A, 
                (byte)0xB7, (byte)0x51, (byte)0x9C, (byte)0xCD, 
                (byte)0x2A, (byte)0x1A, (byte)0x90, (byte)0x6A, 
                (byte)0xE3, (byte)0x0D
            }), new OctetString(new byte[] {
                (byte)0xFC, (byte)0x12, (byte)0x17, (byte)0xD4, 
                (byte)0x32, (byte)0x0A, (byte)0x90, (byte)0x45, 
                (byte)0x2C, (byte)0x76, (byte)0x0A, (byte)0x58, 
                (byte)0xED, (byte)0xCD, (byte)0x30, (byte)0xC8, 
                (byte)0xDD, (byte)0x06, (byte)0x9B, (byte)0x3C, 
                (byte)0x34, (byte)0x45, (byte)0x38, (byte)0x37, 
                (byte)0xA3, (byte)0x4E, (byte)0xD5, (byte)0x0C, 
                (byte)0xB5, (byte)0x49, (byte)0x17, (byte)0xE1, 
                (byte)0xC2, (byte)0x11, (byte)0x2D, (byte)0x84, 
                (byte)0xD1, (byte)0x64, (byte)0xF4, (byte)0x44, 
                (byte)0xF8, (byte)0xF7, (byte)0x47, (byte)0x86, 
                (byte)0x04, (byte)0x6A
            }), null
        ); 
        private static readonly SpecifiedECDomain ECC2PNB368W1 = new SpecifiedECDomain(
            new Integer(1), FieldC2PNB368, CurveC2PNB368W1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x10, (byte)0x85, (byte)0xE2, 
                (byte)0x75, (byte)0x53, (byte)0x81, (byte)0xDC, 
                (byte)0xCC, (byte)0xE3, (byte)0xC1, (byte)0x55, 
                (byte)0x7A, (byte)0xFA, (byte)0x10, (byte)0xC2, 
                (byte)0xF0, (byte)0xC0, (byte)0xC2, (byte)0x82, 
                (byte)0x56, (byte)0x46, (byte)0xC5, (byte)0xB3, 
                (byte)0x4A, (byte)0x39, (byte)0x4C, (byte)0xBC, 
                (byte)0xFA, (byte)0x8B, (byte)0xC1, (byte)0x6B, 
                (byte)0x22, (byte)0xE7, (byte)0xE7, (byte)0x89, 
                (byte)0xE9, (byte)0x27, (byte)0xBE, (byte)0x21, 
                (byte)0x6F, (byte)0x02, (byte)0xE1, (byte)0xFB, 
                (byte)0x13, (byte)0x6A, (byte)0x5F
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x90, (byte)0x51, 
                (byte)0x2D, (byte)0xA9, (byte)0xAF, (byte)0x72, 
                (byte)0xB0, (byte)0x83, (byte)0x49, (byte)0xD9, 
                (byte)0x8A, (byte)0x5D, (byte)0xD4, (byte)0xC7, 
                (byte)0xB0, (byte)0x53, (byte)0x2E, (byte)0xCA, 
                (byte)0x51, (byte)0xCE, (byte)0x03, (byte)0xE2, 
                (byte)0xD1, (byte)0x0F, (byte)0x3B, (byte)0x7A, 
                (byte)0xC5, (byte)0x79, (byte)0xBD, (byte)0x87, 
                (byte)0xE9, (byte)0x09, (byte)0xAE, (byte)0x40, 
                (byte)0xA6, (byte)0xF1, (byte)0x31, (byte)0xE9, 
                (byte)0xCF, (byte)0xCE, (byte)0x5B, (byte)0xD9, 
                (byte)0x67
            })), new Integer(0xFF70), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор c2tnb431r1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldC2TNB431 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(431), 
                new ObjectIdentifier(OID.x962_c2_basis_tp), 
                new Integer(120)
            )
        );
        private static readonly Curve CurveC2TNB431R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x1A, (byte)0x82, (byte)0x7E, (byte)0xF0, 
                (byte)0x0D, (byte)0xD6, (byte)0xFC, (byte)0x0E, 
                (byte)0x23, (byte)0x4C, (byte)0xAF, (byte)0x04, 
                (byte)0x6C, (byte)0x6A, (byte)0x5D, (byte)0x8A, 
                (byte)0x85, (byte)0x39, (byte)0x5B, (byte)0x23, 
                (byte)0x6C, (byte)0xC4, (byte)0xAD, (byte)0x2C, 
                (byte)0xF3, (byte)0x2A, (byte)0x0C, (byte)0xAD, 
                (byte)0xBD, (byte)0xC9, (byte)0xDD, (byte)0xF6, 
                (byte)0x20, (byte)0xB0, (byte)0xEB, (byte)0x99, 
                (byte)0x06, (byte)0xD0, (byte)0x95, (byte)0x7F, 
                (byte)0x6C, (byte)0x6F, (byte)0xEA, (byte)0xCD, 
                (byte)0x61, (byte)0x54, (byte)0x68, (byte)0xDF, 
                (byte)0x10, (byte)0x4D, (byte)0xE2, (byte)0x96, 
                (byte)0xCD, (byte)0x8F
            }), new OctetString(new byte[] {
                (byte)0x10, (byte)0xD9, (byte)0xB4, (byte)0xA3, 
                (byte)0xD9, (byte)0x04, (byte)0x7D, (byte)0x8B, 
                (byte)0x15, (byte)0x43, (byte)0x59, (byte)0xAB, 
                (byte)0xFB, (byte)0x1B, (byte)0x7F, (byte)0x54, 
                (byte)0x85, (byte)0xB0, (byte)0x4C, (byte)0xEB, 
                (byte)0x86, (byte)0x82, (byte)0x37, (byte)0xDD, 
                (byte)0xC9, (byte)0xDE, (byte)0xDA, (byte)0x98, 
                (byte)0x2A, (byte)0x67, (byte)0x9A, (byte)0x5A, 
                (byte)0x91, (byte)0x9B, (byte)0x62, (byte)0x6D, 
                (byte)0x4E, (byte)0x50, (byte)0xA8, (byte)0xDD, 
                (byte)0x73, (byte)0x1B, (byte)0x10, (byte)0x7A, 
                (byte)0x99, (byte)0x62, (byte)0x38, (byte)0x1F, 
                (byte)0xB5, (byte)0xD8, (byte)0x07, (byte)0xBF, 
                (byte)0x26, (byte)0x18
            }), null
        ); 
        private static readonly SpecifiedECDomain ECC2TNB431R1 = new SpecifiedECDomain(
            new Integer(1), FieldC2TNB431, CurveC2TNB431R1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x12, (byte)0x0F, (byte)0xC0, 
                (byte)0x5D, (byte)0x3C, (byte)0x67, (byte)0xA9, 
                (byte)0x9D, (byte)0xE1, (byte)0x61, (byte)0xD2, 
                (byte)0xF4, (byte)0x09, (byte)0x26, (byte)0x22, 
                (byte)0xFE, (byte)0xCA, (byte)0x70, (byte)0x1B, 
                (byte)0xE4, (byte)0xF5, (byte)0x0F, (byte)0x47, 
                (byte)0x58, (byte)0x71, (byte)0x4E, (byte)0x8A, 
                (byte)0x87, (byte)0xBB, (byte)0xF2, (byte)0xA6, 
                (byte)0x58, (byte)0xEF, (byte)0x8C, (byte)0x21, 
                (byte)0xE7, (byte)0xC5, (byte)0xEF, (byte)0xE9, 
                (byte)0x65, (byte)0x36, (byte)0x1F, (byte)0x6C, 
                (byte)0x29, (byte)0x99, (byte)0xC0, (byte)0xC2, 
                (byte)0x47, (byte)0xB0, (byte)0xDB, (byte)0xD7, 
                (byte)0x0C, (byte)0xE6, (byte)0xB7
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x03, (byte)0x40, (byte)0x34, (byte)0x03, 
                (byte)0x40, (byte)0x34, (byte)0x03, (byte)0x40, 
                (byte)0x34, (byte)0x03, (byte)0x40, (byte)0x34, 
                (byte)0x03, (byte)0x40, (byte)0x34, (byte)0x03, 
                (byte)0x40, (byte)0x34, (byte)0x03, (byte)0x40, 
                (byte)0x34, (byte)0x03, (byte)0x40, (byte)0x34, 
                (byte)0x03, (byte)0x40, (byte)0x34, (byte)0x03, 
                (byte)0x23, (byte)0xC3, (byte)0x13, (byte)0xFA, 
                (byte)0xB5, (byte)0x05, (byte)0x89, (byte)0x70, 
                (byte)0x3B, (byte)0x5E, (byte)0xC6, (byte)0x8D, 
                (byte)0x35, (byte)0x87, (byte)0xFE, (byte)0xC6, 
                (byte)0x0D, (byte)0x16, (byte)0x1C, (byte)0xC1, 
                (byte)0x49, (byte)0xC1, (byte)0xAD, (byte)0x4A, 
                (byte)0x91
            })), new Integer(0x2760), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы prime192v1, prime192v2, prime192v3
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldPRIME192 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
            }))
        );
        private static readonly Curve CurvePRIME192V1 = new Curve(
            new OctetString(new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
            }), new OctetString(new byte[] {
                (byte)0x64, (byte)0x21, (byte)0x05, (byte)0x19, 
                (byte)0xE5, (byte)0x9C, (byte)0x80, (byte)0xE7, 
                (byte)0x0F, (byte)0xA7, (byte)0xE9, (byte)0xAB, 
                (byte)0x72, (byte)0x24, (byte)0x30, (byte)0x49, 
                (byte)0xFE, (byte)0xB8, (byte)0xDE, (byte)0xEC, 
                (byte)0xC1, (byte)0x46, (byte)0xB9, (byte)0xB1
            }), new BitString(new byte[] {
                (byte)0x30, (byte)0x45, (byte)0xAE, (byte)0x6F, 
                (byte)0xC8, (byte)0x42, (byte)0x2F, (byte)0x64, 
                (byte)0xED, (byte)0x57, (byte)0x95, (byte)0x28, 
                (byte)0xD3, (byte)0x81, (byte)0x20, (byte)0xEA, 
                (byte)0xE1, (byte)0x21, (byte)0x96, (byte)0xD5
            })
        ); 
        private static readonly SpecifiedECDomain ECPRIME192V1 = new SpecifiedECDomain(
            new Integer(1), FieldPRIME192, CurvePRIME192V1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x18, (byte)0x8D, (byte)0xA8, 
                (byte)0x0E, (byte)0xB0, (byte)0x30, (byte)0x90, 
                (byte)0xF6, (byte)0x7C, (byte)0xBF, (byte)0x20, 
                (byte)0xEB, (byte)0x43, (byte)0xA1, (byte)0x88, 
                (byte)0x00, (byte)0xF4, (byte)0xFF, (byte)0x0A, 
                (byte)0xFD, (byte)0x82, (byte)0xFF, (byte)0x10, 
                (byte)0x12
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x99, (byte)0xDE, (byte)0xF8, (byte)0x36, 
                (byte)0x14, (byte)0x6B, (byte)0xC9, (byte)0xB1, 
                (byte)0xB4, (byte)0xD2, (byte)0x28, (byte)0x31
            })), new Integer(0x01), null
        ); 
        private static readonly Curve CurvePRIME192V2 = new Curve(
            new OctetString(new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
            }), new OctetString(new byte[] {
                (byte)0xCC, (byte)0x22, (byte)0xD6, (byte)0xDF, 
                (byte)0xB9, (byte)0x5C, (byte)0x6B, (byte)0x25, 
                (byte)0xE4, (byte)0x9C, (byte)0x0D, (byte)0x63, 
                (byte)0x64, (byte)0xA4, (byte)0xE5, (byte)0x98, 
                (byte)0x0C, (byte)0x39, (byte)0x3A, (byte)0xA2, 
                (byte)0x16, (byte)0x68, (byte)0xD9, (byte)0x53
            }), new BitString(new byte[] {
                (byte)0x31, (byte)0xA9, (byte)0x2E, (byte)0xE2, 
                (byte)0x02, (byte)0x9F, (byte)0xD1, (byte)0x0D, 
                (byte)0x90, (byte)0x1B, (byte)0x11, (byte)0x3E, 
                (byte)0x99, (byte)0x07, (byte)0x10, (byte)0xF0, 
                (byte)0xD2, (byte)0x1A, (byte)0xC6, (byte)0xB6
            })
        ); 
        private static readonly SpecifiedECDomain ECPRIME192V2 = new SpecifiedECDomain(
            new Integer(1), FieldPRIME192, CurvePRIME192V2, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0xEE, (byte)0xA2, (byte)0xBA, 
                (byte)0xE7, (byte)0xE1, (byte)0x49, (byte)0x78, 
                (byte)0x42, (byte)0xF2, (byte)0xDE, (byte)0x77, 
                (byte)0x69, (byte)0xCF, (byte)0xE9, (byte)0xC9, 
                (byte)0x89, (byte)0xC0, (byte)0x72, (byte)0xAD, 
                (byte)0x69, (byte)0x6F, (byte)0x48, (byte)0x03, 
                (byte)0x4A
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0x5F, (byte)0xB1, (byte)0xA7, (byte)0x24, 
                (byte)0xDC, (byte)0x80, (byte)0x41, (byte)0x86, 
                (byte)0x48, (byte)0xD8, (byte)0xDD, (byte)0x31
            })), new Integer(0x01), null
        ); 
        private static readonly Curve CurvePRIME192V3 = new Curve(
            new OctetString(new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
            }), new OctetString(new byte[] {
                (byte)0x22, (byte)0x12, (byte)0x3D, (byte)0xC2, 
                (byte)0x39, (byte)0x5A, (byte)0x05, (byte)0xCA, 
                (byte)0xA7, (byte)0x42, (byte)0x3D, (byte)0xAE, 
                (byte)0xCC, (byte)0xC9, (byte)0x47, (byte)0x60, 
                (byte)0xA7, (byte)0xD4, (byte)0x62, (byte)0x25, 
                (byte)0x6B, (byte)0xD5, (byte)0x69, (byte)0x16
            }), new BitString(new byte[] {
                (byte)0xC4, (byte)0x69, (byte)0x68, (byte)0x44, 
                (byte)0x35, (byte)0xDE, (byte)0xB3, (byte)0x78, 
                (byte)0xC4, (byte)0xB6, (byte)0x5C, (byte)0xA9, 
                (byte)0x59, (byte)0x1E, (byte)0x2A, (byte)0x57, 
                (byte)0x63, (byte)0x05, (byte)0x9A, (byte)0x2E
            })
        ); 
        private static readonly SpecifiedECDomain ECPRIME192V3 = new SpecifiedECDomain(
            new Integer(1), FieldPRIME192, CurvePRIME192V3, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x7D, (byte)0x29, (byte)0x77, 
                (byte)0x81, (byte)0x00, (byte)0xC6, (byte)0x5A, 
                (byte)0x1D, (byte)0xA1, (byte)0x78, (byte)0x37, 
                (byte)0x16, (byte)0x58, (byte)0x8D, (byte)0xCE, 
                (byte)0x2B, (byte)0x8B, (byte)0x4A, (byte)0xEE, 
                (byte)0x8E, (byte)0x22, (byte)0x8F, (byte)0x18, 
                (byte)0x96
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x7A, (byte)0x62, (byte)0xD0, (byte)0x31, 
                (byte)0xC8, (byte)0x3F, (byte)0x42, (byte)0x94, 
                (byte)0xF6, (byte)0x40, (byte)0xEC, (byte)0x13
            })), new Integer(0x01), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы prime239v1, prime239v2, prime239v3
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldPRIME239 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0x80, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF            
            }))
        );
        private static readonly Curve CurvePRIME239V1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0x80, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFC
            }), new OctetString(new byte[] {
                (byte)0x6B, (byte)0x01, (byte)0x6C, (byte)0x3B, 
                (byte)0xDC, (byte)0xF1, (byte)0x89, (byte)0x41, 
                (byte)0xD0, (byte)0xD6, (byte)0x54, (byte)0x92, 
                (byte)0x14, (byte)0x75, (byte)0xCA, (byte)0x71, 
                (byte)0xA9, (byte)0xDB, (byte)0x2F, (byte)0xB2, 
                (byte)0x7D, (byte)0x1D, (byte)0x37, (byte)0x79, 
                (byte)0x61, (byte)0x85, (byte)0xC2, (byte)0x94, 
                (byte)0x2C, (byte)0x0A
            }), new BitString(new byte[] {
                (byte)0xE4, (byte)0x3B, (byte)0xB4, (byte)0x60, 
                (byte)0xF0, (byte)0xB8, (byte)0x0C, (byte)0xC0, 
                (byte)0xC0, (byte)0xB0, (byte)0x75, (byte)0x79, 
                (byte)0x8E, (byte)0x94, (byte)0x80, (byte)0x60, 
                (byte)0xF8, (byte)0x32, (byte)0x1B, (byte)0x7D
            })
        ); 
        private static readonly SpecifiedECDomain ECPRIME239V1 = new SpecifiedECDomain(
            new Integer(1), FieldPRIME239, CurvePRIME239V1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x0F, (byte)0xFA, (byte)0x96, 
                (byte)0x3C, (byte)0xDC, (byte)0xA8, (byte)0x81, 
                (byte)0x6C, (byte)0xCC, (byte)0x33, (byte)0xB8, 
                (byte)0x64, (byte)0x2B, (byte)0xED, (byte)0xF9, 
                (byte)0x05, (byte)0xC3, (byte)0xD3, (byte)0x58, 
                (byte)0x57, (byte)0x3D, (byte)0x3F, (byte)0x27, 
                (byte)0xFB, (byte)0xBD, (byte)0x3B, (byte)0x3C, 
                (byte)0xB9, (byte)0xAA, (byte)0xAF
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0x9E, 
                (byte)0x5E, (byte)0x9A, (byte)0x9F, (byte)0x5D, 
                (byte)0x90, (byte)0x71, (byte)0xFB, (byte)0xD1, 
                (byte)0x52, (byte)0x26, (byte)0x88, (byte)0x90, 
                (byte)0x9D, (byte)0x0B
            })), new Integer(0x01), null
        ); 
        private static readonly Curve CurvePRIME239V2 = new Curve(
            new OctetString(new byte[] {
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0x80, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFC
            }), new OctetString(new byte[] {
                (byte)0x61, (byte)0x7F, (byte)0xAB, (byte)0x68, 
                (byte)0x32, (byte)0x57, (byte)0x6C, (byte)0xBB, 
                (byte)0xFE, (byte)0xD5, (byte)0x0D, (byte)0x99, 
                (byte)0xF0, (byte)0x24, (byte)0x9C, (byte)0x3F, 
                (byte)0xEE, (byte)0x58, (byte)0xB9, (byte)0x4B, 
                (byte)0xA0, (byte)0x03, (byte)0x8C, (byte)0x7A, 
                (byte)0xE8, (byte)0x4C, (byte)0x8C, (byte)0x83, 
                (byte)0x2F, (byte)0x2C
            }), new BitString(new byte[] {
                (byte)0xE8, (byte)0xB4, (byte)0x01, (byte)0x16, 
                (byte)0x04, (byte)0x09, (byte)0x53, (byte)0x03, 
                (byte)0xCA, (byte)0x3B, (byte)0x80, (byte)0x99, 
                (byte)0x98, (byte)0x2B, (byte)0xE0, (byte)0x9F, 
                (byte)0xCB, (byte)0x9A, (byte)0xE6, (byte)0x16
            })
        ); 
        private static readonly SpecifiedECDomain ECPRIME239V2 = new SpecifiedECDomain(
            new Integer(1), FieldPRIME239, CurvePRIME239V2, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x38, (byte)0xAF, (byte)0x09, 
                (byte)0xD9, (byte)0x87, (byte)0x27, (byte)0x70, 
                (byte)0x51, (byte)0x20, (byte)0xC9, (byte)0x21, 
                (byte)0xBB, (byte)0x5E, (byte)0x9E, (byte)0x26, 
                (byte)0x29, (byte)0x6A, (byte)0x3C, (byte)0xDC, 
                (byte)0xF2, (byte)0xF3, (byte)0x57, (byte)0x57, 
                (byte)0xA0, (byte)0xEA, (byte)0xFD, (byte)0x87, 
                (byte)0xB8, (byte)0x30, (byte)0xE7
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x80, (byte)0x00, (byte)0x00, (byte)0xCF, 
                (byte)0xA7, (byte)0xE8, (byte)0x59, (byte)0x43, 
                (byte)0x77, (byte)0xD4, (byte)0x14, (byte)0xC0, 
                (byte)0x38, (byte)0x21, (byte)0xBC, (byte)0x58, 
                (byte)0x20, (byte)0x63
            })), new Integer(0x01), null
        ); 
        private static readonly Curve CurvePRIME239V3 = new Curve(
            new OctetString(new byte[] {
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0x80, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFC
            }), new OctetString(new byte[] {
                (byte)0x25, (byte)0x57, (byte)0x05, (byte)0xFA, 
                (byte)0x2A, (byte)0x30, (byte)0x66, (byte)0x54, 
                (byte)0xB1, (byte)0xF4, (byte)0xCB, (byte)0x03, 
                (byte)0xD6, (byte)0xA7, (byte)0x50, (byte)0xA3, 
                (byte)0x0C, (byte)0x25, (byte)0x01, (byte)0x02, 
                (byte)0xD4, (byte)0x98, (byte)0x87, (byte)0x17, 
                (byte)0xD9, (byte)0xBA, (byte)0x15, (byte)0xAB, 
                (byte)0x6D, (byte)0x3E
            }), new BitString(new byte[] {
                (byte)0x7D, (byte)0x73, (byte)0x74, (byte)0x16, 
                (byte)0x8F, (byte)0xFE, (byte)0x34, (byte)0x71, 
                (byte)0xB6, (byte)0x0A, (byte)0x85, (byte)0x76, 
                (byte)0x86, (byte)0xA1, (byte)0x94, (byte)0x75, 
                (byte)0xD3, (byte)0xBF, (byte)0xA2, (byte)0xFF
            })
        ); 
        private static readonly SpecifiedECDomain ECPRIME239V3 = new SpecifiedECDomain(
            new Integer(1), FieldPRIME239, CurvePRIME239V3, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x67, (byte)0x68, (byte)0xAE, 
                (byte)0x8E, (byte)0x18, (byte)0xBB, (byte)0x92, 
                (byte)0xCF, (byte)0xCF, (byte)0x00, (byte)0x5C, 
                (byte)0x94, (byte)0x9A, (byte)0xA2, (byte)0xC6, 
                (byte)0xD9, (byte)0x48, (byte)0x53, (byte)0xD0, 
                (byte)0xE6, (byte)0x60, (byte)0xBB, (byte)0xF8, 
                (byte)0x54, (byte)0xB1, (byte)0xC9, (byte)0x50, 
                (byte)0x5F, (byte)0xE9, (byte)0x5A
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0x97, 
                (byte)0x5D, (byte)0xEB, (byte)0x41, (byte)0xB3, 
                (byte)0xA6, (byte)0x05, (byte)0x7C, (byte)0x3C, 
                (byte)0x43, (byte)0x21, (byte)0x46, (byte)0x52, 
                (byte)0x65, (byte)0x51
            })), new Integer(0x01), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор prime256v1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldPRIME256 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
            }))
        );
        private static readonly Curve CurvePRIME256V1 = new Curve(
            new OctetString(new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
            }), new OctetString(new byte[] {
                (byte)0x5A, (byte)0xC6, (byte)0x35, (byte)0xD8, 
                (byte)0xAA, (byte)0x3A, (byte)0x93, (byte)0xE7, 
                (byte)0xB3, (byte)0xEB, (byte)0xBD, (byte)0x55, 
                (byte)0x76, (byte)0x98, (byte)0x86, (byte)0xBC, 
                (byte)0x65, (byte)0x1D, (byte)0x06, (byte)0xB0, 
                (byte)0xCC, (byte)0x53, (byte)0xB0, (byte)0xF6, 
                (byte)0x3B, (byte)0xCE, (byte)0x3C, (byte)0x3E, 
                (byte)0x27, (byte)0xD2, (byte)0x60, (byte)0x4B
            }), new BitString(new byte[] {
                (byte)0xC4, (byte)0x9D, (byte)0x36, (byte)0x08, 
                (byte)0x86, (byte)0xE7, (byte)0x04, (byte)0x93, 
                (byte)0x6A, (byte)0x66, (byte)0x78, (byte)0xE1, 
                (byte)0x13, (byte)0x9D, (byte)0x26, (byte)0xB7, 
                (byte)0x81, (byte)0x9F, (byte)0x7E, (byte)0x90
            })
        ); 
        private static readonly SpecifiedECDomain ECPRIME256V1 = new SpecifiedECDomain(
            new Integer(1), FieldPRIME256, CurvePRIME256V1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x6B, (byte)0x17, (byte)0xD1, 
                (byte)0xF2, (byte)0xE1, (byte)0x2C, (byte)0x42, 
                (byte)0x47, (byte)0xF8, (byte)0xBC, (byte)0xE6, 
                (byte)0xE5, (byte)0x63, (byte)0xA4, (byte)0x40, 
                (byte)0xF2, (byte)0x77, (byte)0x03, (byte)0x7D, 
                (byte)0x81, (byte)0x2D, (byte)0xEB, (byte)0x33, 
                (byte)0xA0, (byte)0xF4, (byte)0xA1, (byte)0x39, 
                (byte)0x45, (byte)0xD8, (byte)0x98, (byte)0xC2, 
                (byte)0x96
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xBC, (byte)0xE6, (byte)0xFA, (byte)0xAD, 
                (byte)0xA7, (byte)0x17, (byte)0x9E, (byte)0x84, 
                (byte)0xF3, (byte)0xB9, (byte)0xCA, (byte)0xC2, 
                (byte)0xFC, (byte)0x63, (byte)0x25, (byte)0x51
            })), new Integer(0x01), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы secp112r1, secp112r2
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECP112 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xDB, (byte)0x7C, (byte)0x2A, (byte)0xBF, 
                (byte)0x62, (byte)0xE3, (byte)0x5E, (byte)0x66, 
                (byte)0x80, (byte)0x76, (byte)0xBE, (byte)0xAD, 
                (byte)0x20, (byte)0x8B
            }))
        );
        private static readonly Curve CurveSECP112R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0xDB, (byte)0x7C, (byte)0x2A, (byte)0xBF, 
                (byte)0x62, (byte)0xE3, (byte)0x5E, (byte)0x66, 
                (byte)0x80, (byte)0x76, (byte)0xBE, (byte)0xAD, 
                (byte)0x20, (byte)0x88
            }), new OctetString(new byte[] {
                (byte)0x65, (byte)0x9E, (byte)0xF8, (byte)0xBA, 
                (byte)0x04, (byte)0x39, (byte)0x16, (byte)0xEE, 
                (byte)0xDE, (byte)0x89, (byte)0x11, (byte)0x70, 
                (byte)0x2B, (byte)0x22
            }), new BitString(new byte[] {
                (byte)0x00, (byte)0xF5, (byte)0x0B, (byte)0x02, 
                (byte)0x8E, (byte)0x4D, (byte)0x69, (byte)0x6E, 
                (byte)0x67, (byte)0x68, (byte)0x75, (byte)0x61, 
                (byte)0x51, (byte)0x75, (byte)0x29, (byte)0x04, 
                (byte)0x72, (byte)0x78, (byte)0x3F, (byte)0xB1
            })
        ); 
        private static readonly SpecifiedECDomain ECSECP112R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECP112, CurveSECP112R1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x09, (byte)0x48, (byte)0x72, 
                (byte)0x39, (byte)0x99, (byte)0x5A, (byte)0x5E, 
                (byte)0xE7, (byte)0x6B, (byte)0x55, (byte)0xF9, 
                (byte)0xC2, (byte)0xF0, (byte)0x98        
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xDB, (byte)0x7C, (byte)0x2A, (byte)0xBF, 
                (byte)0x62, (byte)0xE3, (byte)0x5E, (byte)0x76, 
                (byte)0x28, (byte)0xDF, (byte)0xAC, (byte)0x65, 
                (byte)0x61, (byte)0xC5
            })), new Integer(0x01), null
        ); 
        private static readonly Curve CurveSECP112R2 = new Curve(
            new OctetString(new byte[] {
                (byte)0x61, (byte)0x27, (byte)0xC2, (byte)0x4C, 
                (byte)0x05, (byte)0xF3, (byte)0x8A, (byte)0x0A, 
                (byte)0xAA, (byte)0xF6, (byte)0x5C, (byte)0x0E, 
                (byte)0xF0, (byte)0x2C
            }), new OctetString(new byte[] {
                (byte)0x51, (byte)0xDE, (byte)0xF1, (byte)0x81, 
                (byte)0x5D, (byte)0xB5, (byte)0xED, (byte)0x74, 
                (byte)0xFC, (byte)0xC3, (byte)0x4C, (byte)0x85, 
                (byte)0xD7, (byte)0x09
            }), new BitString(new byte[] {
                (byte)0x00, (byte)0x27, (byte)0x57, (byte)0xA1, 
                (byte)0x11, (byte)0x4D, (byte)0x69, (byte)0x6E, 
                (byte)0x67, (byte)0x68, (byte)0x75, (byte)0x61, 
                (byte)0x51, (byte)0x75, (byte)0x53, (byte)0x16, 
                (byte)0xC0, (byte)0x5E, (byte)0x0B, (byte)0xD4
            })
        ); 
        private static readonly SpecifiedECDomain ECSECP112R2 = new SpecifiedECDomain(
            new Integer(1), FieldSECP112, CurveSECP112R2, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x4B, (byte)0xA3, (byte)0x0A, 
                (byte)0xB5, (byte)0xE8, (byte)0x92, (byte)0xB4, 
                (byte)0xE1, (byte)0x64, (byte)0x9D, (byte)0xD0, 
                (byte)0x92, (byte)0x86, (byte)0x43
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x36, (byte)0xDF, (byte)0x0A, (byte)0xAF, 
                (byte)0xD8, (byte)0xB8, (byte)0xD7, (byte)0x59, 
                (byte)0x7C, (byte)0xA1, (byte)0x05, (byte)0x20, 
                (byte)0xD0, (byte)0x4B
            })), new Integer(0x04), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы secp128r1, secp128r2
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECP128 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFD, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
            }))
        );
        private static readonly Curve CurveSECP128R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFD, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
            }), new OctetString(new byte[] {
                (byte)0xE8, (byte)0x75, (byte)0x79, (byte)0xC1, 
                (byte)0x10, (byte)0x79, (byte)0xF4, (byte)0x3D, 
                (byte)0xD8, (byte)0x24, (byte)0x99, (byte)0x3C, 
                (byte)0x2C, (byte)0xEE, (byte)0x5E, (byte)0xD3
            }), new BitString(new byte[] {
                (byte)0x00, (byte)0x0E, (byte)0x0D, (byte)0x4D, 
                (byte)0x69, (byte)0x6E, (byte)0x67, (byte)0x68, 
                (byte)0x75, (byte)0x61, (byte)0x51, (byte)0x75, 
                (byte)0x0C, (byte)0xC0, (byte)0x3A, (byte)0x44, 
                (byte)0x73, (byte)0xD0, (byte)0x36, (byte)0x79
            })
        ); 
        private static readonly SpecifiedECDomain ECSECP128R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECP128, CurveSECP128R1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x16, (byte)0x1F, (byte)0xF7, 
                (byte)0x52, (byte)0x8B, (byte)0x89, (byte)0x9B, 
                (byte)0x2D, (byte)0x0C, (byte)0x28, (byte)0x60, 
                (byte)0x7C, (byte)0xA5, (byte)0x2C, (byte)0x5B, 
                (byte)0x86
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x75, (byte)0xA3, (byte)0x0D, (byte)0x1B, 
                (byte)0x90, (byte)0x38, (byte)0xA1, (byte)0x15
            })), new Integer(0x01), null
        ); 
        private static readonly Curve CurveSECP128R2 = new Curve(
            new OctetString(new byte[] {
                (byte)0xD6, (byte)0x03, (byte)0x19, (byte)0x98, 
                (byte)0xD1, (byte)0xB3, (byte)0xBB, (byte)0xFE, 
                (byte)0xBF, (byte)0x59, (byte)0xCC, (byte)0x9B, 
                (byte)0xBF, (byte)0xF9, (byte)0xAE, (byte)0xE1
            }), new OctetString(new byte[] {
                (byte)0x5E, (byte)0xEE, (byte)0xFC, (byte)0xA3, 
                (byte)0x80, (byte)0xD0, (byte)0x29, (byte)0x19, 
                (byte)0xDC, (byte)0x2C, (byte)0x65, (byte)0x58, 
                (byte)0xBB, (byte)0x6D, (byte)0x8A, (byte)0x5D
            }), new BitString(new byte[] {
                (byte)0x00, (byte)0x4D, (byte)0x69, (byte)0x6E, 
                (byte)0x67, (byte)0x68, (byte)0x75, (byte)0x61, 
                (byte)0x51, (byte)0x75, (byte)0x12, (byte)0xD8, 
                (byte)0xF0, (byte)0x34, (byte)0x31, (byte)0xFC, 
                (byte)0xE6, (byte)0x3B, (byte)0x88, (byte)0xF4
            })
        ); 
        private static readonly SpecifiedECDomain ECSECP128R2 = new SpecifiedECDomain(
            new Integer(1), FieldSECP128, CurveSECP128R2, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x7B, (byte)0x6A, (byte)0xA5, 
                (byte)0xD8, (byte)0x5E, (byte)0x57, (byte)0x29, 
                (byte)0x83, (byte)0xE6, (byte)0xFB, (byte)0x32, 
                (byte)0xA7, (byte)0xCD, (byte)0xEB, (byte)0xC1, 
                (byte)0x40
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x3F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xBE, (byte)0x00, (byte)0x24, (byte)0x72, 
                (byte)0x06, (byte)0x13, (byte)0xB5, (byte)0xA3
            })), new Integer(0x04), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор secp160k1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECP160K1 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xAC, (byte)0x73
            }))
        );
        private static readonly Curve CurveSECP160K1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x07
            }), null
        ); 
        private static readonly SpecifiedECDomain ECSECP160K1 = new SpecifiedECDomain(
            new Integer(1), FieldSECP160K1, CurveSECP160K1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x3B, (byte)0x4C, (byte)0x38, 
                (byte)0x2C, (byte)0xE3, (byte)0x7A, (byte)0xA1, 
                (byte)0x92, (byte)0xA4, (byte)0x01, (byte)0x9E, 
                (byte)0x76, (byte)0x30, (byte)0x36, (byte)0xF4, 
                (byte)0xF5, (byte)0xDD, (byte)0x4D, (byte)0x7E, 
                (byte)0xBB
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x01, (byte)0xB8, 
                (byte)0xFA, (byte)0x16, (byte)0xDF, (byte)0xAB, 
                (byte)0x9A, (byte)0xCA, (byte)0x16, (byte)0xB6, 
                (byte)0xB3
            })), new Integer(0x01), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы secp160r1, secp160r2
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECP160R1 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF
            }))
        );
        private static readonly Curve CurveSECP160R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFC
            }), new OctetString(new byte[] {
                (byte)0x1C, (byte)0x97, (byte)0xBE, (byte)0xFC, 
                (byte)0x54, (byte)0xBD, (byte)0x7A, (byte)0x8B, 
                (byte)0x65, (byte)0xAC, (byte)0xF8, (byte)0x9F, 
                (byte)0x81, (byte)0xD4, (byte)0xD4, (byte)0xAD, 
                (byte)0xC5, (byte)0x65, (byte)0xFA, (byte)0x45
            }), new BitString(new byte[] {
                (byte)0x10, (byte)0x53, (byte)0xCD, (byte)0xE4, 
                (byte)0x2C, (byte)0x14, (byte)0xD6, (byte)0x96, 
                (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
                (byte)0x15, (byte)0x17, (byte)0x53, (byte)0x3B, 
                (byte)0xF3, (byte)0xF8, (byte)0x33, (byte)0x45
            })
        ); 
        private static readonly SpecifiedECDomain ECSECP160R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECP160R1, CurveSECP160R1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x4A, (byte)0x96, (byte)0xB5, 
                (byte)0x68, (byte)0x8E, (byte)0xF5, (byte)0x73, 
                (byte)0x28, (byte)0x46, (byte)0x64, (byte)0x69, 
                (byte)0x89, (byte)0x68, (byte)0xC3, (byte)0x8B, 
                (byte)0xB9, (byte)0x13, (byte)0xCB, (byte)0xFC, 
                (byte)0x82
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x01, (byte)0xF4, 
                (byte)0xC8, (byte)0xF9, (byte)0x27, (byte)0xAE, 
                (byte)0xD3, (byte)0xCA, (byte)0x75, (byte)0x22, 
                (byte)0x57
            })), new Integer(0x01), null
        ); 
        private static readonly FieldID FieldSECP160R2 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xAC, (byte)0x73
            }))
        );
        private static readonly Curve CurveSECP160R2 = new Curve(
            new OctetString(new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xAC, (byte)0x70
            }), new OctetString(new byte[] {
                (byte)0xB4, (byte)0xE1, (byte)0x34, (byte)0xD3, 
                (byte)0xFB, (byte)0x59, (byte)0xEB, (byte)0x8B, 
                (byte)0xAB, (byte)0x57, (byte)0x27, (byte)0x49, 
                (byte)0x04, (byte)0x66, (byte)0x4D, (byte)0x5A, 
                (byte)0xF5, (byte)0x03, (byte)0x88, (byte)0xBA
            }), new BitString(new byte[] {
                (byte)0xB9, (byte)0x9B, (byte)0x99, (byte)0xB0, 
                (byte)0x99, (byte)0xB3, (byte)0x23, (byte)0xE0, 
                (byte)0x27, (byte)0x09, (byte)0xA4, (byte)0xD6, 
                (byte)0x96, (byte)0xE6, (byte)0x76, (byte)0x87, 
                (byte)0x56, (byte)0x15, (byte)0x17, (byte)0x51
            })
        ); 
        private static readonly SpecifiedECDomain ECSECP160R2 = new SpecifiedECDomain(
            new Integer(1), FieldSECP160R2, CurveSECP160R2, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x52, (byte)0xDC, (byte)0xB0, 
                (byte)0x34, (byte)0x29, (byte)0x3A, (byte)0x11, 
                (byte)0x7E, (byte)0x1F, (byte)0x4F, (byte)0xF1, 
                (byte)0x1B, (byte)0x30, (byte)0xF7, (byte)0x19, 
                (byte)0x9D, (byte)0x31, (byte)0x44, (byte)0xCE, 
                (byte)0x6D
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x35, 
                (byte)0x1E, (byte)0xE7, (byte)0x86, (byte)0xA8, 
                (byte)0x18, (byte)0xF3, (byte)0xA1, (byte)0xA1, 
                (byte)0x6B
            })), new Integer(0x01), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор secp192k1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECP192K1 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xEE, (byte)0x37
            }))
        );
        private static readonly Curve CurveSECP192K1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03
            }), null
        ); 
        private static readonly SpecifiedECDomain ECSECP192K1 = new SpecifiedECDomain(
            new Integer(1), FieldSECP192K1, CurveSECP192K1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0xDB, (byte)0x4F, (byte)0xF1, 
                (byte)0x0E, (byte)0xC0, (byte)0x57, (byte)0xE9, 
                (byte)0xAE, (byte)0x26, (byte)0xB0, (byte)0x7D, 
                (byte)0x02, (byte)0x80, (byte)0xB7, (byte)0xF4, 
                (byte)0x34, (byte)0x1D, (byte)0xA5, (byte)0xD1, 
                (byte)0xB1, (byte)0xEA, (byte)0xE0, (byte)0x6C, 
                (byte)0x7D
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0x26, (byte)0xF2, (byte)0xFC, (byte)0x17, 
                (byte)0x0F, (byte)0x69, (byte)0x46, (byte)0x6A, 
                (byte)0x74, (byte)0xDE, (byte)0xFD, (byte)0x8D
            })), new Integer(0x01), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор secp224k1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECP224K1 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xE5, (byte)0x6D
            }))
        );
        private static readonly Curve CurveSECP224K1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x05
            }), null
        ); 
        private static readonly SpecifiedECDomain ECSECP224K1 = new SpecifiedECDomain(
            new Integer(1), FieldSECP224K1, CurveSECP224K1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0xA1, (byte)0x45, (byte)0x5B, 
                (byte)0x33, (byte)0x4D, (byte)0xF0, (byte)0x99, 
                (byte)0xDF, (byte)0x30, (byte)0xFC, (byte)0x28, 
                (byte)0xA1, (byte)0x69, (byte)0xA4, (byte)0x67, 
                (byte)0xE9, (byte)0xE4, (byte)0x70, (byte)0x75, 
                (byte)0xA9, (byte)0x0F, (byte)0x7E, (byte)0x65, 
                (byte)0x0E, (byte)0xB6, (byte)0xB7, (byte)0xA4, 
                (byte)0x5C
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x01, (byte)0xDC, 
                (byte)0xE8, (byte)0xD2, (byte)0xEC, (byte)0x61, 
                (byte)0x84, (byte)0xCA, (byte)0xF0, (byte)0xA9, 
                (byte)0x71, (byte)0x76, (byte)0x9F, (byte)0xB1, 
                (byte)0xF7
            })), new Integer(0x01), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор secp224r1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECP224R1 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
            }))
        );
        private static readonly Curve CurveSECP224R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE
            }), new OctetString(new byte[] {
                (byte)0xB4, (byte)0x05, (byte)0x0A, (byte)0x85, 
                (byte)0x0C, (byte)0x04, (byte)0xB3, (byte)0xAB, 
                (byte)0xF5, (byte)0x41, (byte)0x32, (byte)0x56, 
                (byte)0x50, (byte)0x44, (byte)0xB0, (byte)0xB7, 
                (byte)0xD7, (byte)0xBF, (byte)0xD8, (byte)0xBA, 
                (byte)0x27, (byte)0x0B, (byte)0x39, (byte)0x43, 
                (byte)0x23, (byte)0x55, (byte)0xFF, (byte)0xB4
            }), new BitString(new byte[] {
                (byte)0xBD, (byte)0x71, (byte)0x34, (byte)0x47, 
                (byte)0x99, (byte)0xD5, (byte)0xC7, (byte)0xFC, 
                (byte)0xDC, (byte)0x45, (byte)0xB5, (byte)0x9F, 
                (byte)0xA3, (byte)0xB9, (byte)0xAB, (byte)0x8F, 
                (byte)0x6A, (byte)0x94, (byte)0x8B, (byte)0xC5
            })
        ); 
        private static readonly SpecifiedECDomain ECSECP224R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECP224R1, CurveSECP224R1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0xB7, (byte)0x0E, (byte)0x0C, 
                (byte)0xBD, (byte)0x6B, (byte)0xB4, (byte)0xBF, 
                (byte)0x7F, (byte)0x32, (byte)0x13, (byte)0x90, 
                (byte)0xB9, (byte)0x4A, (byte)0x03, (byte)0xC1, 
                (byte)0xD3, (byte)0x56, (byte)0xC2, (byte)0x11, 
                (byte)0x22, (byte)0x34, (byte)0x32, (byte)0x80, 
                (byte)0xD6, (byte)0x11, (byte)0x5C, (byte)0x1D, 
                (byte)0x21
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0x16, (byte)0xA2, 
                (byte)0xE0, (byte)0xB8, (byte)0xF0, (byte)0x3E, 
                (byte)0x13, (byte)0xDD, (byte)0x29, (byte)0x45, 
                (byte)0x5C, (byte)0x5C, (byte)0x2A, (byte)0x3D
            })), new Integer(0x01), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор secp256k1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECP256K1 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xFC, (byte)0x2F
            }))
        );
        private static readonly Curve CurveSECP256K1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x07
            }), null
        ); 
        private static readonly SpecifiedECDomain ECSECP256K1 = new SpecifiedECDomain(
            new Integer(1), FieldSECP256K1, CurveSECP256K1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x79, (byte)0xBE, (byte)0x66, 
                (byte)0x7E, (byte)0xF9, (byte)0xDC, (byte)0xBB, 
                (byte)0xAC, (byte)0x55, (byte)0xA0, (byte)0x62, 
                (byte)0x95, (byte)0xCE, (byte)0x87, (byte)0x0B, 
                (byte)0x07, (byte)0x02, (byte)0x9B, (byte)0xFC, 
                (byte)0xDB, (byte)0x2D, (byte)0xCE, (byte)0x28, 
                (byte)0xD9, (byte)0x59, (byte)0xF2, (byte)0x81, 
                (byte)0x5B, (byte)0x16, (byte)0xF8, (byte)0x17, 
                (byte)0x98
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xBA, (byte)0xAE, (byte)0xDC, (byte)0xE6, 
                (byte)0xAF, (byte)0x48, (byte)0xA0, (byte)0x3B, 
                (byte)0xBF, (byte)0xD2, (byte)0x5E, (byte)0x8C,
                (byte)0xD0, (byte)0x36, (byte)0x41, (byte)0x41
            })), new Integer(0x01), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор secp384r1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECP384R1 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF
            }))
        );
        private static readonly Curve CurveSECP384R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFE, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFC
            }), new OctetString(new byte[] {
                (byte)0xB3, (byte)0x31, (byte)0x2F, (byte)0xA7, 
                (byte)0xE2, (byte)0x3E, (byte)0xE7, (byte)0xE4, 
                (byte)0x98, (byte)0x8E, (byte)0x05, (byte)0x6B, 
                (byte)0xE3, (byte)0xF8, (byte)0x2D, (byte)0x19, 
                (byte)0x18, (byte)0x1D, (byte)0x9C, (byte)0x6E, 
                (byte)0xFE, (byte)0x81, (byte)0x41, (byte)0x12, 
                (byte)0x03, (byte)0x14, (byte)0x08, (byte)0x8F,
                (byte)0x50, (byte)0x13, (byte)0x87, (byte)0x5A, 
                (byte)0xC6, (byte)0x56, (byte)0x39, (byte)0x8D, 
                (byte)0x8A, (byte)0x2E, (byte)0xD1, (byte)0x9D, 
                (byte)0x2A, (byte)0x85, (byte)0xC8, (byte)0xED, 
                (byte)0xD3, (byte)0xEC, (byte)0x2A, (byte)0xEF
            }), new BitString(new byte[] {
                (byte)0xA3, (byte)0x35, (byte)0x92, (byte)0x6A, 
                (byte)0xA3, (byte)0x19, (byte)0xA2, (byte)0x7A, 
                (byte)0x1D, (byte)0x00, (byte)0x89, (byte)0x6A, 
                (byte)0x67, (byte)0x73, (byte)0xA4, (byte)0x82, 
                (byte)0x7A, (byte)0xCD, (byte)0xAC, (byte)0x73
            })
        ); 
        private static readonly SpecifiedECDomain ECSECP384R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECP384R1, CurveSECP384R1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0xAA, (byte)0x87, (byte)0xCA, 
                (byte)0x22, (byte)0xBE, (byte)0x8B, (byte)0x05, 
                (byte)0x37, (byte)0x8E, (byte)0xB1, (byte)0xC7, 
                (byte)0x1E, (byte)0xF3, (byte)0x20, (byte)0xAD, 
                (byte)0x74, (byte)0x6E, (byte)0x1D, (byte)0x3B, 
                (byte)0x62, (byte)0x8B, (byte)0xA7, (byte)0x9B, 
                (byte)0x98, (byte)0x59, (byte)0xF7, (byte)0x41, 
                (byte)0xE0, (byte)0x82, (byte)0x54, (byte)0x2A, 
                (byte)0x38, (byte)0x55, (byte)0x02, (byte)0xF2, 
                (byte)0x5D, (byte)0xBF, (byte)0x55, (byte)0x29, 
                (byte)0x6C, (byte)0x3A, (byte)0x54, (byte)0x5E, 
                (byte)0x38, (byte)0x72, (byte)0x76, (byte)0x0A,
                (byte)0xB7
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xC7, (byte)0x63, (byte)0x4D, (byte)0x81,
                (byte)0xF4, (byte)0x37, (byte)0x2D, (byte)0xDF, 
                (byte)0x58, (byte)0x1A, (byte)0x0D, (byte)0xB2, 
                (byte)0x48, (byte)0xB0, (byte)0xA7, (byte)0x7A, 
                (byte)0xEC, (byte)0xEC, (byte)0x19, (byte)0x6A, 
                (byte)0xCC, (byte)0xC5, (byte)0x29, (byte)0x73
            })), new Integer(0x01), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Набор secp521r1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECP521R1 = new FieldID(
            new ObjectIdentifier(OID.x962_prime_field), 
            new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF
            }))
        );
        private static readonly Curve CurveSECP521R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x01, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFC
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x51, (byte)0x95, (byte)0x3E, 
                (byte)0xB9, (byte)0x61, (byte)0x8E, (byte)0x1C, 
                (byte)0x9A, (byte)0x1F, (byte)0x92, (byte)0x9A, 
                (byte)0x21, (byte)0xA0, (byte)0xB6, (byte)0x85, 
                (byte)0x40, (byte)0xEE, (byte)0xA2, (byte)0xDA, 
                (byte)0x72, (byte)0x5B, (byte)0x99, (byte)0xB3, 
                (byte)0x15, (byte)0xF3, (byte)0xB8, (byte)0xB4, 
                (byte)0x89, (byte)0x91, (byte)0x8E, (byte)0xF1, 
                (byte)0x09, (byte)0xE1, (byte)0x56, (byte)0x19, 
                (byte)0x39, (byte)0x51, (byte)0xEC, (byte)0x7E, 
                (byte)0x93, (byte)0x7B, (byte)0x16, (byte)0x52, 
                (byte)0xC0, (byte)0xBD, (byte)0x3B, (byte)0xB1, 
                (byte)0xBF, (byte)0x07, (byte)0x35, (byte)0x73, 
                (byte)0xDF, (byte)0x88, (byte)0x3D, (byte)0x2C, 
                (byte)0x34, (byte)0xF1, (byte)0xEF, (byte)0x45, 
                (byte)0x1F, (byte)0xD4, (byte)0x6B, (byte)0x50, 
                (byte)0x3F, (byte)0x00
            }), new BitString(new byte[] {
                (byte)0xD0, (byte)0x9E, (byte)0x88, (byte)0x00, 
                (byte)0x29, (byte)0x1C, (byte)0xB8, (byte)0x53, 
                (byte)0x96, (byte)0xCC, (byte)0x67, (byte)0x17, 
                (byte)0x39, (byte)0x32, (byte)0x84, (byte)0xAA, 
                (byte)0xA0, (byte)0xDA, (byte)0x64, (byte)0xBA
            })
        ); 
        private static readonly SpecifiedECDomain ECSECP521R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECP521R1, CurveSECP521R1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x00, (byte)0xC6, (byte)0x85, 
                (byte)0x8E, (byte)0x06, (byte)0xB7, (byte)0x04, 
                (byte)0x04, (byte)0xE9, (byte)0xCD, (byte)0x9E, 
                (byte)0x3E, (byte)0xCB, (byte)0x66, (byte)0x23, 
                (byte)0x95, (byte)0xB4, (byte)0x42, (byte)0x9C, 
                (byte)0x64, (byte)0x81, (byte)0x39, (byte)0x05, 
                (byte)0x3F, (byte)0xB5, (byte)0x21, (byte)0xF8, 
                (byte)0x28, (byte)0xAF, (byte)0x60, (byte)0x6B, 
                (byte)0x4D, (byte)0x3D, (byte)0xBA, (byte)0xA1, 
                (byte)0x4B, (byte)0x5E, (byte)0x77, (byte)0xEF, 
                (byte)0xE7, (byte)0x59, (byte)0x28, (byte)0xFE, 
                (byte)0x1D, (byte)0xC1, (byte)0x27, (byte)0xA2, 
                (byte)0xFF, (byte)0xA8, (byte)0xDE, (byte)0x33, 
                (byte)0x48, (byte)0xB3, (byte)0xC1, (byte)0x85, 
                (byte)0x6A, (byte)0x42, (byte)0x9B, (byte)0xF9, 
                (byte)0x7E, (byte)0x7E, (byte)0x31, (byte)0xC2, 
                (byte)0xE5, (byte)0xBD, (byte)0x66
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFA, (byte)0x51, (byte)0x86, 
                (byte)0x87, (byte)0x83, (byte)0xBF, (byte)0x2F, 
                (byte)0x96, (byte)0x6B, (byte)0x7F, (byte)0xCC, 
                (byte)0x01, (byte)0x48, (byte)0xF7, (byte)0x09, 
                (byte)0xA5, (byte)0xD0, (byte)0x3B, (byte)0xB5, 
                (byte)0xC9, (byte)0xB8, (byte)0x89, (byte)0x9C, 
                (byte)0x47, (byte)0xAE, (byte)0xBB, (byte)0x6F, 
                (byte)0xB7, (byte)0x1E, (byte)0x91, (byte)0x38, 
                (byte)0x64, (byte)0x09
            })), new Integer(0x01), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы sect113r1, sect113r2
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECT113 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(113), 
                new ObjectIdentifier(OID.x962_c2_basis_tp), 
                new Integer(9)
            )
        );
        private static readonly Curve CurveSECT113R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x30, (byte)0x88, (byte)0x25, 
                (byte)0x0C, (byte)0xA6, (byte)0xE7, (byte)0xC7, 
                (byte)0xFE, (byte)0x64, (byte)0x9C, (byte)0xE8, 
                (byte)0x58, (byte)0x20, (byte)0xF7
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0xE8, (byte)0xBE, (byte)0xE4, 
                (byte)0xD3, (byte)0xE2, (byte)0x26, (byte)0x07, 
                (byte)0x44, (byte)0x18, (byte)0x8B, (byte)0xE0, 
                (byte)0xE9, (byte)0xC7, (byte)0x23
            }), new BitString(new byte[] {
                (byte)0x10, (byte)0xE7, (byte)0x23, (byte)0xAB, 
                (byte)0x14, (byte)0xD6, (byte)0x96, (byte)0xE6, 
                (byte)0x76, (byte)0x87, (byte)0x56, (byte)0x15, 
                (byte)0x17, (byte)0x56, (byte)0xFE, (byte)0xBF, 
                (byte)0x8F, (byte)0xCB, (byte)0x49, (byte)0xA9
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT113R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT113, CurveSECT113R1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x00, (byte)0x9D, (byte)0x73, 
                (byte)0x61, (byte)0x6F, (byte)0x35, (byte)0xF4, 
                (byte)0xAB, (byte)0x14, (byte)0x07, (byte)0xD7, 
                (byte)0x35, (byte)0x62, (byte)0xC1, (byte)0x0F
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0xD9, (byte)0xCC, (byte)0xEC, (byte)0x8A, 
                (byte)0x39, (byte)0xE5, (byte)0x6F
            })), new Integer(0x02), null
        ); 
        private static readonly Curve CurveSECT113R2 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x68, (byte)0x99, (byte)0x18, 
                (byte)0xDB, (byte)0xEC, (byte)0x7E, (byte)0x5A, 
                (byte)0x0D, (byte)0xD6, (byte)0xDF, (byte)0xC0, 
                (byte)0xAA, (byte)0x55, (byte)0xC7
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x95, (byte)0xE9, (byte)0xA9, 
                (byte)0xEC, (byte)0x9B, (byte)0x29, (byte)0x7B, 
                (byte)0xD4, (byte)0xBF, (byte)0x36, (byte)0xE0, 
                (byte)0x59, (byte)0x18, (byte)0x4F
            }), new BitString(new byte[] {
                (byte)0x10, (byte)0xC0, (byte)0xFB, (byte)0x15, 
                (byte)0x76, (byte)0x08, (byte)0x60, (byte)0xDE, 
                (byte)0xF1, (byte)0xEE, (byte)0xF4, (byte)0xD6, 
                (byte)0x96, (byte)0xE6, (byte)0x76, (byte)0x87, 
                (byte)0x56, (byte)0x15, (byte)0x17, (byte)0x5D
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT113R2 = new SpecifiedECDomain(
            new Integer(1), FieldSECT113, CurveSECT113R2, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x01, (byte)0xA5, (byte)0x7A, 
                (byte)0x6A, (byte)0x7B, (byte)0x26, (byte)0xCA, 
                (byte)0x5E, (byte)0xF5, (byte)0x2F, (byte)0xCD, 
                (byte)0xB8, (byte)0x16, (byte)0x47, (byte)0x97
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, 
                (byte)0x08, (byte)0x78, (byte)0x9B, (byte)0x24, 
                (byte)0x96, (byte)0xAF, (byte)0x93
            })), new Integer(0x02), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы sect131r1, sect131r2
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECT131 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(131), 
                new ObjectIdentifier(OID.x962_c2_basis_pp), 
                new Pentanomial(new Integer(2), new Integer(3), new Integer(8))
            )
        );
        private static readonly Curve CurveSECT131R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x07, (byte)0xA1, (byte)0x1B, (byte)0x09, 
                (byte)0xA7, (byte)0x6B, (byte)0x56, (byte)0x21, 
                (byte)0x44, (byte)0x41, (byte)0x8F, (byte)0xF3, 
                (byte)0xFF, (byte)0x8C, (byte)0x25, (byte)0x70, 
                (byte)0xB8
            }), new OctetString(new byte[] {
                (byte)0x02, (byte)0x17, (byte)0xC0, (byte)0x56, 
                (byte)0x10, (byte)0x88, (byte)0x4B, (byte)0x63, 
                (byte)0xB9, (byte)0xC6, (byte)0xC7, (byte)0x29, 
                (byte)0x16, (byte)0x78, (byte)0xF9, (byte)0xD3, 
                (byte)0x41
            }), new BitString(new byte[] {
                (byte)0x4D, (byte)0x69, (byte)0x6E, (byte)0x67, 
                (byte)0x68, (byte)0x75, (byte)0x61, (byte)0x51, 
                (byte)0x75, (byte)0x98, (byte)0x5B, (byte)0xD3, 
                (byte)0xAD, (byte)0xBA, (byte)0xDA, (byte)0x21, 
                (byte)0xB4, (byte)0x3A, (byte)0x97, (byte)0xE2
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT131R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT131, CurveSECT131R1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x00, (byte)0x81, (byte)0xBA, 
                (byte)0xF9, (byte)0x1F, (byte)0xDF, (byte)0x98, 
                (byte)0x33, (byte)0xC4, (byte)0x0F, (byte)0x9C, 
                (byte)0x18, (byte)0x13, (byte)0x43, (byte)0x63, 
                (byte)0x83, (byte)0x99
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x02, (byte)0x31, (byte)0x23, (byte)0x95, 
                (byte)0x3A, (byte)0x94, (byte)0x64, (byte)0xB5, 
                (byte)0x4D
            })), new Integer(0x02), null
        ); 
        private static readonly Curve CurveSECT131R2 = new Curve(
            new OctetString(new byte[] {
                (byte)0x03, (byte)0xE5, (byte)0xA8, (byte)0x89, 
                (byte)0x19, (byte)0xD7, (byte)0xCA, (byte)0xFC, 
                (byte)0xBF, (byte)0x41, (byte)0x5F, (byte)0x07, 
                (byte)0xC2, (byte)0x17, (byte)0x65, (byte)0x73, 
                (byte)0xB2
            }), new OctetString(new byte[] {
                (byte)0x04, (byte)0xB8, (byte)0x26, (byte)0x6A, 
                (byte)0x46, (byte)0xC5, (byte)0x56, (byte)0x57, 
                (byte)0xAC, (byte)0x73, (byte)0x4C, (byte)0xE3, 
                (byte)0x8F, (byte)0x01, (byte)0x8F, (byte)0x21, 
                (byte)0x92
            }), new BitString(new byte[] {
                (byte)0x98, (byte)0x5B, (byte)0xD3, (byte)0xAD, 
                (byte)0xBA, (byte)0xD4, (byte)0xD6, (byte)0x96, 
                (byte)0xE6, (byte)0x76, (byte)0x87, (byte)0x56, 
                (byte)0x15, (byte)0x17, (byte)0x5A, (byte)0x21, 
                (byte)0xB4, (byte)0x3A, (byte)0x97, (byte)0xE3
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT131R2 = new SpecifiedECDomain(
            new Integer(1), FieldSECT131, CurveSECT131R2, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x03, (byte)0x56, (byte)0xDC, 
                (byte)0xD8, (byte)0xF2, (byte)0xF9, (byte)0x50, 
                (byte)0x31, (byte)0xAD, (byte)0x65, (byte)0x2D, 
                (byte)0x23, (byte)0x95, (byte)0x1B, (byte)0xB3, 
                (byte)0x66, (byte)0xA8
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x01, (byte)0x69, (byte)0x54, (byte)0xA2, 
                (byte)0x33, (byte)0x04, (byte)0x9B, (byte)0xA9, 
                (byte)0x8F
            })), new Integer(0x02), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы sect163k1, sect163r1, sect163r2
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECT163 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(163), 
                new ObjectIdentifier(OID.x962_c2_basis_pp), 
                new Pentanomial(new Integer(3), new Integer(6), new Integer(7))
            )
        );
        private static readonly Curve CurveSECT163K1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x01
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x01
            }), null
        ); 
        private static readonly SpecifiedECDomain ECSECT163K1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT163, CurveSECT163K1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x02, (byte)0xFE, (byte)0x13, 
                (byte)0xC0, (byte)0x53, (byte)0x7B, (byte)0xBC, 
                (byte)0x11, (byte)0xAC, (byte)0xAA, (byte)0x07, 
                (byte)0xD7, (byte)0x93, (byte)0xDE, (byte)0x4E, 
                (byte)0x6D, (byte)0x5E, (byte)0x5C, (byte)0x94, 
                (byte)0xEE, (byte)0xE8
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x01, 
                (byte)0x08, (byte)0xA2, (byte)0xE0, (byte)0xCC, 
                (byte)0x0D, (byte)0x99, (byte)0xF8, (byte)0xA5, 
                (byte)0xEF
            })), new Integer(0x02), null
        ); 
        private static readonly Curve CurveSECT163R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x07, (byte)0xB6, (byte)0x88, (byte)0x2C, 
                (byte)0xAA, (byte)0xEF, (byte)0xA8, (byte)0x4F, 
                (byte)0x95, (byte)0x54, (byte)0xFF, (byte)0x84, 
                (byte)0x28, (byte)0xBD, (byte)0x88, (byte)0xE2, 
                (byte)0x46, (byte)0xD2, (byte)0x78, (byte)0x2A, 
                (byte)0xE2
            }), new OctetString(new byte[] {
                (byte)0x07, (byte)0x13, (byte)0x61, (byte)0x2D, 
                (byte)0xCD, (byte)0xDC, (byte)0xB4, (byte)0x0A, 
                (byte)0xAB, (byte)0x94, (byte)0x6B, (byte)0xDA, 
                (byte)0x29, (byte)0xCA, (byte)0x91, (byte)0xF7, 
                (byte)0x3A, (byte)0xF9, (byte)0x58, (byte)0xAF, 
                (byte)0xD9
            }), new BitString(new byte[] {
                (byte)0x24, (byte)0xB7, (byte)0xB1, (byte)0x37, 
                (byte)0xC8, (byte)0xA1, (byte)0x4D, (byte)0x69, 
                (byte)0x6E, (byte)0x67, (byte)0x68, (byte)0x75, 
                (byte)0x61, (byte)0x51, (byte)0x75, (byte)0x6F, 
                (byte)0xD0, (byte)0xDA, (byte)0x2E, (byte)0x5C
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT163R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT163, CurveSECT163R1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x03, (byte)0x69, (byte)0x97, 
                (byte)0x96, (byte)0x97, (byte)0xAB, (byte)0x43, 
                (byte)0x89, (byte)0x77, (byte)0x89, (byte)0x56, 
                (byte)0x67, (byte)0x89, (byte)0x56, (byte)0x7F, 
                (byte)0x78, (byte)0x7A, (byte)0x78, (byte)0x76, 
                (byte)0xA6, (byte)0x54
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x03, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0x48, 
                (byte)0xAA, (byte)0xB6, (byte)0x89, (byte)0xC2, 
                (byte)0x9C, (byte)0xA7, (byte)0x10, (byte)0x27, 
                (byte)0x9B
            })), new Integer(0x02), null
        ); 
        private static readonly Curve CurveSECT163R2 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x01
            }), new OctetString(new byte[] {
                (byte)0x02, (byte)0x0A, (byte)0x60, (byte)0x19, 
                (byte)0x07, (byte)0xB8, (byte)0xC9, (byte)0x53, 
                (byte)0xCA, (byte)0x14, (byte)0x81, (byte)0xEB, 
                (byte)0x10, (byte)0x51, (byte)0x2F, (byte)0x78, 
                (byte)0x74, (byte)0x4A, (byte)0x32, (byte)0x05, 
                (byte)0xFD
            }), new BitString(new byte[] {
                (byte)0x85, (byte)0xE2, (byte)0x5B, (byte)0xFE, 
                (byte)0x5C, (byte)0x86, (byte)0x22, (byte)0x6C, 
                (byte)0xDB, (byte)0x12, (byte)0x01, (byte)0x6F, 
                (byte)0x75, (byte)0x53, (byte)0xF9, (byte)0xD0, 
                (byte)0xE6, (byte)0x93, (byte)0xA2, (byte)0x68
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT163R2 = new SpecifiedECDomain(
            new Integer(1), FieldSECT163, CurveSECT163R2, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x03, (byte)0xF0, (byte)0xEB, 
                (byte)0xA1, (byte)0x62, (byte)0x86, (byte)0xA2, 
                (byte)0xD5, (byte)0x7E, (byte)0xA0, (byte)0x99, 
                (byte)0x11, (byte)0x68, (byte)0xD4, (byte)0x99, 
                (byte)0x46, (byte)0x37, (byte)0xE8, (byte)0x34, 
                (byte)0x3E, (byte)0x36
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x92, 
                (byte)0xFE, (byte)0x77, (byte)0xE7, (byte)0x0C, 
                (byte)0x12, (byte)0xA4, (byte)0x23, (byte)0x4C, 
                (byte)0x33
            })), new Integer(0x02), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы sect193r1, sect193r2
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECT193 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(193), 
                new ObjectIdentifier(OID.x962_c2_basis_tp), 
                new Integer(15)
            )
        );
        private static readonly Curve CurveSECT193R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x17, (byte)0x85, (byte)0x8F, 
                (byte)0xEB, (byte)0x7A, (byte)0x98, (byte)0x97, 
                (byte)0x51, (byte)0x69, (byte)0xE1, (byte)0x71, 
                (byte)0xF7, (byte)0x7B, (byte)0x40, (byte)0x87, 
                (byte)0xDE, (byte)0x09, (byte)0x8A, (byte)0xC8, 
                (byte)0xA9, (byte)0x11, (byte)0xDF, (byte)0x7B, 
                (byte)0x01
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0xFD, (byte)0xFB, (byte)0x49, 
                (byte)0xBF, (byte)0xE6, (byte)0xC3, (byte)0xA8, 
                (byte)0x9F, (byte)0xAC, (byte)0xAD, (byte)0xAA, 
                (byte)0x7A, (byte)0x1E, (byte)0x5B, (byte)0xBC, 
                (byte)0x7C, (byte)0xC1, (byte)0xC2, (byte)0xE5, 
                (byte)0xD8, (byte)0x31, (byte)0x47, (byte)0x88, 
                (byte)0x14
            }), new BitString(new byte[] {
                (byte)0x10, (byte)0x3F, (byte)0xAE, (byte)0xC7, 
                (byte)0x4D, (byte)0x69, (byte)0x6E, (byte)0x67, 
                (byte)0x68, (byte)0x75, (byte)0x61, (byte)0x51, 
                (byte)0x75, (byte)0x77, (byte)0x7F, (byte)0xC5, 
                (byte)0xB1, (byte)0x91, (byte)0xEF, (byte)0x30
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT193R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT193, CurveSECT193R1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x01, (byte)0xF4, (byte)0x81, 
                (byte)0xBC, (byte)0x5F, (byte)0x0F, (byte)0xF8, 
                (byte)0x4A, (byte)0x74, (byte)0xAD, (byte)0x6C, 
                (byte)0xDF, (byte)0x6F, (byte)0xDE, (byte)0xF4, 
                (byte)0xBF, (byte)0x61, (byte)0x79, (byte)0x62, 
                (byte)0x53, (byte)0x72, (byte)0xD8, (byte)0xC0, 
                (byte)0xC5, (byte)0xE1
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0xC7, (byte)0xF3, (byte)0x4A, 
                (byte)0x77, (byte)0x8F, (byte)0x44, (byte)0x3A, 
                (byte)0xCC, (byte)0x92, (byte)0x0E, (byte)0xBA, 
                (byte)0x49
            })), new Integer(0x02), null
        ); 
        private static readonly Curve CurveSECT193R2 = new Curve(
            new OctetString(new byte[] {
                (byte)0x01, (byte)0x63, (byte)0xF3, (byte)0x5A, 
                (byte)0x51, (byte)0x37, (byte)0xC2, (byte)0xCE, 
                (byte)0x3E, (byte)0xA6, (byte)0xED, (byte)0x86, 
                (byte)0x67, (byte)0x19, (byte)0x0B, (byte)0x0B, 
                (byte)0xC4, (byte)0x3E, (byte)0xCD, (byte)0x69, 
                (byte)0x97, (byte)0x77, (byte)0x02, (byte)0x70, 
                (byte)0x9B
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0xC9, (byte)0xBB, (byte)0x9E, 
                (byte)0x89, (byte)0x27, (byte)0xD4, (byte)0xD6, 
                (byte)0x4C, (byte)0x37, (byte)0x7E, (byte)0x2A, 
                (byte)0xB2, (byte)0x85, (byte)0x6A, (byte)0x5B, 
                (byte)0x16, (byte)0xE3, (byte)0xEF, (byte)0xB7, 
                (byte)0xF6, (byte)0x1D, (byte)0x43, (byte)0x16, 
                (byte)0xAE
            }), new BitString(new byte[] {
                (byte)0x10, (byte)0xB7, (byte)0xB4, (byte)0xD6, 
                (byte)0x96, (byte)0xE6, (byte)0x76, (byte)0x87, 
                (byte)0x56, (byte)0x15, (byte)0x17, (byte)0x51, 
                (byte)0x37, (byte)0xC8, (byte)0xA1, (byte)0x6F, 
                (byte)0xD0, (byte)0xDA, (byte)0x22, (byte)0x11
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT193R2 = new SpecifiedECDomain(
            new Integer(1), FieldSECT193, CurveSECT193R2, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x00, (byte)0xD9, (byte)0xB6, 
                (byte)0x7D, (byte)0x19, (byte)0x2E, (byte)0x03, 
                (byte)0x67, (byte)0xC8, (byte)0x03, (byte)0xF3, 
                (byte)0x9E, (byte)0x1A, (byte)0x7E, (byte)0x82, 
                (byte)0xCA, (byte)0x14, (byte)0xA6, (byte)0x51, 
                (byte)0x35, (byte)0x0A, (byte)0xAE, (byte)0x61, 
                (byte)0x7E, (byte)0x8F
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x01, (byte)0x5A, (byte)0xAB, (byte)0x56, 
                (byte)0x1B, (byte)0x00, (byte)0x54, (byte)0x13, 
                (byte)0xCC, (byte)0xD4, (byte)0xEE, (byte)0x99, 
                (byte)0xD5
            })), new Integer(0x02), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы sect233k1, sect233r1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECT233 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(233), 
                new ObjectIdentifier(OID.x962_c2_basis_tp), 
                new Integer(74)
            )
        );
        private static readonly Curve CurveSECT233K1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x01
            }), null
        ); 
        private static readonly SpecifiedECDomain ECSECT233K1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT233, CurveSECT233K1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x01, (byte)0x72, (byte)0x32, 
                (byte)0xBA, (byte)0x85, (byte)0x3A, (byte)0x7E, 
                (byte)0x73, (byte)0x1A, (byte)0xF1, (byte)0x29, 
                (byte)0xF2, (byte)0x2F, (byte)0xF4, (byte)0x14, 
                (byte)0x95, (byte)0x63, (byte)0xA4, (byte)0x19, 
                (byte)0xC2, (byte)0x6B, (byte)0xF5, (byte)0x0A, 
                (byte)0x4C, (byte)0x9D, (byte)0x6E, (byte)0xEF, 
                (byte)0xAD, (byte)0x61, (byte)0x26
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x06, (byte)0x9D, 
                (byte)0x5B, (byte)0xB9, (byte)0x15, (byte)0xBC, 
                (byte)0xD4, (byte)0x6E, (byte)0xFB, (byte)0x1A, 
                (byte)0xD5, (byte)0xF1, (byte)0x73, (byte)0xAB, 
                (byte)0xDF
            })), new Integer(0x04), null
        ); 
        private static readonly Curve CurveSECT233R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x01
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x66, (byte)0x64, (byte)0x7E, 
                (byte)0xDE, (byte)0x6C, (byte)0x33, (byte)0x2C, 
                (byte)0x7F, (byte)0x8C, (byte)0x09, (byte)0x23, 
                (byte)0xBB, (byte)0x58, (byte)0x21, (byte)0x3B, 
                (byte)0x33, (byte)0x3B, (byte)0x20, (byte)0xE9, 
                (byte)0xCE, (byte)0x42, (byte)0x81, (byte)0xFE, 
                (byte)0x11, (byte)0x5F, (byte)0x7D, (byte)0x8F, 
                (byte)0x90, (byte)0xAD
            }), new BitString(new byte[] {
                (byte)0x74, (byte)0xD5, (byte)0x9F, (byte)0xF0, 
                (byte)0x7F, (byte)0x6B, (byte)0x41, (byte)0x3D, 
                (byte)0x0E, (byte)0xA1, (byte)0x4B, (byte)0x34, 
                (byte)0x4B, (byte)0x20, (byte)0xA2, (byte)0xDB, 
                (byte)0x04, (byte)0x9B, (byte)0x50, (byte)0xC3
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT233R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT233, CurveSECT233R1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x00, (byte)0xFA, (byte)0xC9, 
                (byte)0xDF, (byte)0xCB, (byte)0xAC, (byte)0x83, 
                (byte)0x13, (byte)0xBB, (byte)0x21, (byte)0x39, 
                (byte)0xF1, (byte)0xBB, (byte)0x75, (byte)0x5F, 
                (byte)0xEF, (byte)0x65, (byte)0xBC, (byte)0x39, 
                (byte)0x1F, (byte)0x8B, (byte)0x36, (byte)0xF8, 
                (byte)0xF8, (byte)0xEB, (byte)0x73, (byte)0x71, 
                (byte)0xFD, (byte)0x55, (byte)0x8B
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x13, 
                (byte)0xE9, (byte)0x74, (byte)0xE7, (byte)0x2F, 
                (byte)0x8A, (byte)0x69, (byte)0x22, (byte)0x03, 
                (byte)0x1D, (byte)0x26, (byte)0x03, (byte)0xCF, 
                (byte)0xE0, (byte)0xD7
            })), new Integer(0x02), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы sect233k1, sect233r1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECT239 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(239), 
                new ObjectIdentifier(OID.x962_c2_basis_tp), 
                new Integer(158)
            )
        );
        private static readonly Curve CurveSECT239K1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x01
            }), null
        ); 
        private static readonly SpecifiedECDomain ECSECT239K1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT239, CurveSECT239K1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x29, (byte)0xA0, (byte)0xB6, 
                (byte)0xA8, (byte)0x87, (byte)0xA9, (byte)0x83, 
                (byte)0xE9, (byte)0x73, (byte)0x09, (byte)0x88, 
                (byte)0xA6, (byte)0x87, (byte)0x27, (byte)0xA8, 
                (byte)0xB2, (byte)0xD1, (byte)0x26, (byte)0xC4, 
                (byte)0x4C, (byte)0xC2, (byte)0xCC, (byte)0x7B, 
                (byte)0x2A, (byte)0x65, (byte)0x55, (byte)0x19, 
                (byte)0x30, (byte)0x35, (byte)0xDC
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x5A, 
                (byte)0x79, (byte)0xFE, (byte)0xC6, (byte)0x7C, 
                (byte)0xB6, (byte)0xE9, (byte)0x1F, (byte)0x1C, 
                (byte)0x1D, (byte)0xA8, (byte)0x00, (byte)0xE4, 
                (byte)0x78, (byte)0xA5
            })), new Integer(0x04), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы sect283k1, sect283r1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECT283 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(283), 
                new ObjectIdentifier(OID.x962_c2_basis_pp), 
                new Pentanomial(new Integer(5), new Integer(7), new Integer(12))
            )
        );
        private static readonly Curve CurveSECT283K1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
            }), null
        ); 
        private static readonly SpecifiedECDomain ECSECT283K1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT283, CurveSECT283K1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x05, (byte)0x03, (byte)0x21, 
                (byte)0x3F, (byte)0x78, (byte)0xCA, (byte)0x44, 
                (byte)0x88, (byte)0x3F, (byte)0x1A, (byte)0x3B, 
                (byte)0x81, (byte)0x62, (byte)0xF1, (byte)0x88, 
                (byte)0xE5, (byte)0x53, (byte)0xCD, (byte)0x26, 
                (byte)0x5F, (byte)0x23, (byte)0xC1, (byte)0x56, 
                (byte)0x7A, (byte)0x16, (byte)0x87, (byte)0x69, 
                (byte)0x13, (byte)0xB0, (byte)0xC2, (byte)0xAC, 
                (byte)0x24, (byte)0x58, (byte)0x49, (byte)0x28, 
                (byte)0x36
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xE9, (byte)0xAE, 
                (byte)0x2E, (byte)0xD0, (byte)0x75, (byte)0x77, 
                (byte)0x26, (byte)0x5D, (byte)0xFF, (byte)0x7F, 
                (byte)0x94, (byte)0x45, (byte)0x1E, (byte)0x06, 
                (byte)0x1E, (byte)0x16, (byte)0x3C, (byte)0x61
            })), new Integer(0x04), null
        ); 
        private static readonly Curve CurveSECT283R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
            }), new OctetString(new byte[] {
                (byte)0x02, (byte)0x7B, (byte)0x68, (byte)0x0A, 
                (byte)0xC8, (byte)0xB8, (byte)0x59, (byte)0x6D, 
                (byte)0xA5, (byte)0xA4, (byte)0xAF, (byte)0x8A, 
                (byte)0x19, (byte)0xA0, (byte)0x30, (byte)0x3F, 
                (byte)0xCA, (byte)0x97, (byte)0xFD, (byte)0x76, 
                (byte)0x45, (byte)0x30, (byte)0x9F, (byte)0xA2, 
                (byte)0xA5, (byte)0x81, (byte)0x48, (byte)0x5A,
                (byte)0xF6, (byte)0x26, (byte)0x3E, (byte)0x31, 
                (byte)0x3B, (byte)0x79, (byte)0xA2, (byte)0xF5
            }), new BitString(new byte[] {
                (byte)0x77, (byte)0xE2, (byte)0xB0, (byte)0x73, 
                (byte)0x70, (byte)0xEB, (byte)0x0F, (byte)0x83, 
                (byte)0x2A, (byte)0x6D, (byte)0xD5, (byte)0xB6, 
                (byte)0x2D, (byte)0xFC, (byte)0x88, (byte)0xCD, 
                (byte)0x06, (byte)0xBB, (byte)0x84, (byte)0xBE
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT283R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT283, CurveSECT283R1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x05, (byte)0xF9, (byte)0x39, 
                (byte)0x25, (byte)0x8D, (byte)0xB7, (byte)0xDD, 
                (byte)0x90, (byte)0xE1, (byte)0x93, (byte)0x4F, 
                (byte)0x8C, (byte)0x70, (byte)0xB0, (byte)0xDF, 
                (byte)0xEC, (byte)0x2E, (byte)0xED, (byte)0x25, 
                (byte)0xB8, (byte)0x55, (byte)0x7E, (byte)0xAC, 
                (byte)0x9C, (byte)0x80, (byte)0xE2, (byte)0xE1, 
                (byte)0x98, (byte)0xF8, (byte)0xCD, (byte)0xBE, 
                (byte)0xCD, (byte)0x86, (byte)0xB1, (byte)0x20, 
                (byte)0x53
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x03, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xEF, (byte)0x90, 
                (byte)0x39, (byte)0x96, (byte)0x60, (byte)0xFC, 
                (byte)0x93, (byte)0x8A, (byte)0x90, (byte)0x16, 
                (byte)0x5B, (byte)0x04, (byte)0x2A, (byte)0x7C, 
                (byte)0xEF, (byte)0xAD, (byte)0xB3, (byte)0x07
            })), new Integer(0x02), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы sect409k1, sect409r1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECT409 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(409), 
                new ObjectIdentifier(OID.x962_c2_basis_tp), 
                new Integer(87)
            )
        );
        private static readonly Curve CurveSECT409K1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
            }), null
        ); 
        private static readonly SpecifiedECDomain ECSECT409K1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT409, CurveSECT409K1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x00, (byte)0x60, (byte)0xF0, 
                (byte)0x5F, (byte)0x65, (byte)0x8F, (byte)0x49, 
                (byte)0xC1, (byte)0xAD, (byte)0x3A, (byte)0xB1, 
                (byte)0x89, (byte)0x0F, (byte)0x71, (byte)0x84, 
                (byte)0x21, (byte)0x0E, (byte)0xFD, (byte)0x09, 
                (byte)0x87, (byte)0xE3, (byte)0x07, (byte)0xC8, 
                (byte)0x4C, (byte)0x27, (byte)0xAC, (byte)0xCF, 
                (byte)0xB8, (byte)0xF9, (byte)0xF6, (byte)0x7C, 
                (byte)0xC2, (byte)0xC4, (byte)0x60, (byte)0x18, 
                (byte)0x9E, (byte)0xB5, (byte)0xAA, (byte)0xAA, 
                (byte)0x62, (byte)0xEE, (byte)0x22, (byte)0x2E, 
                (byte)0xB1, (byte)0xB3, (byte)0x55, (byte)0x40, 
                (byte)0xCF, (byte)0xE9, (byte)0x02, (byte)0x37, 
                (byte)0x46
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFE, (byte)0x5F, (byte)0x83, 
                (byte)0xB2, (byte)0xD4, (byte)0xEA, (byte)0x20, 
                (byte)0x40, (byte)0x0E, (byte)0xC4, (byte)0x55, 
                (byte)0x7D, (byte)0x5E, (byte)0xD3, (byte)0xE3, 
                (byte)0xE7, (byte)0xCA, (byte)0x5B, (byte)0x4B, 
                (byte)0x5C, (byte)0x83, (byte)0xB8, (byte)0xE0, 
                (byte)0x1E, (byte)0x5F, (byte)0xCF
            })), new Integer(0x04), null
        ); 
        private static readonly Curve CurveSECT409R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x21, (byte)0xA5, (byte)0xC2, 
                (byte)0xC8, (byte)0xEE, (byte)0x9F, (byte)0xEB, 
                (byte)0x5C, (byte)0x4B, (byte)0x9A, (byte)0x75, 
                (byte)0x3B, (byte)0x7B, (byte)0x47, (byte)0x6B, 
                (byte)0x7F, (byte)0xD6, (byte)0x42, (byte)0x2E, 
                (byte)0xF1, (byte)0xF3, (byte)0xDD, (byte)0x67, 
                (byte)0x47, (byte)0x61, (byte)0xFA, (byte)0x99, 
                (byte)0xD6, (byte)0xAC, (byte)0x27, (byte)0xC8, 
                (byte)0xA9, (byte)0xA1, (byte)0x97, (byte)0xB2, 
                (byte)0x72, (byte)0x82, (byte)0x2F, (byte)0x6C, 
                (byte)0xD5, (byte)0x7A, (byte)0x55, (byte)0xAA, 
                (byte)0x4F, (byte)0x50, (byte)0xAE, (byte)0x31, 
                (byte)0x7B, (byte)0x13, (byte)0x54, (byte)0x5F
            }), new BitString(new byte[] {
                (byte)0x40, (byte)0x99, (byte)0xB5, (byte)0xA4, 
                (byte)0x57, (byte)0xF9, (byte)0xD6, (byte)0x9F, 
                (byte)0x79, (byte)0x21, (byte)0x3D, (byte)0x09, 
                (byte)0x4C, (byte)0x4B, (byte)0xCD, (byte)0x4D, 
                (byte)0x42, (byte)0x62, (byte)0x21, (byte)0x0B
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT409R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT409, CurveSECT409R1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x01, (byte)0x5D, (byte)0x48, 
                (byte)0x60, (byte)0xD0, (byte)0x88, (byte)0xDD, 
                (byte)0xB3, (byte)0x49, (byte)0x6B, (byte)0x0C, 
                (byte)0x60, (byte)0x64, (byte)0x75, (byte)0x62, 
                (byte)0x60, (byte)0x44, (byte)0x1C, (byte)0xDE, 
                (byte)0x4A, (byte)0xF1, (byte)0x77, (byte)0x1D, 
                (byte)0x4D, (byte)0xB0, (byte)0x1F, (byte)0xFE, 
                (byte)0x5B, (byte)0x34, (byte)0xE5, (byte)0x97, 
                (byte)0x03, (byte)0xDC, (byte)0x25, (byte)0x5A, 
                (byte)0x86, (byte)0x8A, (byte)0x11, (byte)0x80, 
                (byte)0x51, (byte)0x56, (byte)0x03, (byte)0xAE, 
                (byte)0xAB, (byte)0x60, (byte)0x79, (byte)0x4E, 
                (byte)0x54, (byte)0xBB, (byte)0x79, (byte)0x96, 
                (byte)0xA7
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x01, (byte)0xE2, 
                (byte)0xAA, (byte)0xD6, (byte)0xA6, (byte)0x12, 
                (byte)0xF3, (byte)0x33, (byte)0x07, (byte)0xBE, 
                (byte)0x5F, (byte)0xA4, (byte)0x7C, (byte)0x3C, 
                (byte)0x9E, (byte)0x05, (byte)0x2F, (byte)0x83, 
                (byte)0x81, (byte)0x64, (byte)0xCD, (byte)0x37, 
                (byte)0xD9, (byte)0xA2, (byte)0x11, (byte)0x73
            })), new Integer(0x02), null
        ); 
        ////////////////////////////////////////////////////////////////////////////
        // Наборы sect571k1, sect571r1
        ////////////////////////////////////////////////////////////////////////////
        private static readonly FieldID FieldSECT571 = new FieldID(
            new ObjectIdentifier(OID.x962_c2_field), 
            new CharacteristicTwo(new Integer(571), 
                new ObjectIdentifier(OID.x962_c2_basis_pp), 
                new Pentanomial(new Integer(2), new Integer(5), new Integer(10))
            )
        );
        private static readonly Curve CurveSECT571K1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
            }), new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
            }), null
        ); 
        private static readonly SpecifiedECDomain ECSECT571K1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT571, CurveSECT571K1, 
            new OctetString(new byte[] {
                (byte)0x02, (byte)0x02, (byte)0x6E, (byte)0xB7, 
                (byte)0xA8, (byte)0x59, (byte)0x92, (byte)0x3F, 
                (byte)0xBC, (byte)0x82, (byte)0x18, (byte)0x96, 
                (byte)0x31, (byte)0xF8, (byte)0x10, (byte)0x3F, 
                (byte)0xE4, (byte)0xAC, (byte)0x9C, (byte)0xA2, 
                (byte)0x97, (byte)0x00, (byte)0x12, (byte)0xD5, 
                (byte)0xD4, (byte)0x60, (byte)0x24, (byte)0x80, 
                (byte)0x48, (byte)0x01, (byte)0x84, (byte)0x1C, 
                (byte)0xA4, (byte)0x43, (byte)0x70, (byte)0x95, 
                (byte)0x84, (byte)0x93, (byte)0xB2, (byte)0x05, 
                (byte)0xE6, (byte)0x47, (byte)0xDA, (byte)0x30, 
                (byte)0x4D, (byte)0xB4, (byte)0xCE, (byte)0xB0, 
                (byte)0x8C, (byte)0xBB, (byte)0xD1, (byte)0xBA, 
                (byte)0x39, (byte)0x49, (byte)0x47, (byte)0x76, 
                (byte)0xFB, (byte)0x98, (byte)0x8B, (byte)0x47, 
                (byte)0x17, (byte)0x4D, (byte)0xCA, (byte)0x88, 
                (byte)0xC7, (byte)0xE2, (byte)0x94, (byte)0x52, 
                (byte)0x83, (byte)0xA0, (byte)0x1C, (byte)0x89, 
                (byte)0x72
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x13, (byte)0x18, (byte)0x50, (byte)0xE1, 
                (byte)0xF1, (byte)0x9A, (byte)0x63, (byte)0xE4, 
                (byte)0xB3, (byte)0x91, (byte)0xA8, (byte)0xDB, 
                (byte)0x91, (byte)0x7F, (byte)0x41, (byte)0x38, 
                (byte)0xB6, (byte)0x30, (byte)0xD8, (byte)0x4B,
                (byte)0xE5, (byte)0xD6, (byte)0x39, (byte)0x38, 
                (byte)0x1E, (byte)0x91, (byte)0xDE, (byte)0xB4, 
                (byte)0x5C, (byte)0xFE, (byte)0x77, (byte)0x8F, 
                (byte)0x63, (byte)0x7C, (byte)0x10, (byte)0x01
            })), new Integer(0x04), null
        ); 
        private static readonly Curve CurveSECT571R1 = new Curve(
            new OctetString(new byte[] {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01
            }), new OctetString(new byte[] {
                (byte)0x02, (byte)0xF4, (byte)0x0E, (byte)0x7E, 
                (byte)0x22, (byte)0x21, (byte)0xF2, (byte)0x95, 
                (byte)0xDE, (byte)0x29, (byte)0x71, (byte)0x17, 
                (byte)0xB7, (byte)0xF3, (byte)0xD6, (byte)0x2F, 
                (byte)0x5C, (byte)0x6A, (byte)0x97, (byte)0xFF, 
                (byte)0xCB, (byte)0x8C, (byte)0xEF, (byte)0xF1, 
                (byte)0xCD, (byte)0x6B, (byte)0xA8, (byte)0xCE, 
                (byte)0x4A, (byte)0x9A, (byte)0x18, (byte)0xAD, 
                (byte)0x84, (byte)0xFF, (byte)0xAB, (byte)0xBD, 
                (byte)0x8E, (byte)0xFA, (byte)0x59, (byte)0x33, 
                (byte)0x2B, (byte)0xE7, (byte)0xAD, (byte)0x67, 
                (byte)0x56, (byte)0xA6, (byte)0x6E, (byte)0x29, 
                (byte)0x4A, (byte)0xFD, (byte)0x18, (byte)0x5A, 
                (byte)0x78, (byte)0xFF, (byte)0x12, (byte)0xAA, 
                (byte)0x52, (byte)0x0E, (byte)0x4D, (byte)0xE7, 
                (byte)0x39, (byte)0xBA, (byte)0xCA, (byte)0x0C, 
                (byte)0x7F, (byte)0xFE, (byte)0xFF, (byte)0x7F, 
                (byte)0x29, (byte)0x55, (byte)0x72, (byte)0x7A
            }), new BitString(new byte[] {
                (byte)0x2A, (byte)0xA0, (byte)0x58, (byte)0xF7, 
                (byte)0x3A, (byte)0x0E, (byte)0x33, (byte)0xAB, 
                (byte)0x48, (byte)0x6B, (byte)0x0F, (byte)0x61, 
                (byte)0x04, (byte)0x10, (byte)0xC5, (byte)0x3A, 
                (byte)0x7F, (byte)0x13, (byte)0x23, (byte)0x10
            })
        ); 
        private static readonly SpecifiedECDomain ECSECT571R1 = new SpecifiedECDomain(
            new Integer(1), FieldSECT571, CurveSECT571R1, 
            new OctetString(new byte[] {
                (byte)0x03, (byte)0x03, (byte)0x03, (byte)0x00, 
                (byte)0x1D, (byte)0x34, (byte)0xB8, (byte)0x56, 
                (byte)0x29, (byte)0x6C, (byte)0x16, (byte)0xC0, 
                (byte)0xD4, (byte)0x0D, (byte)0x3C, (byte)0xD7, 
                (byte)0x75, (byte)0x0A, (byte)0x93, (byte)0xD1, 
                (byte)0xD2, (byte)0x95, (byte)0x5F, (byte)0xA8, 
                (byte)0x0A, (byte)0xA5, (byte)0xF4, (byte)0x0F, 
                (byte)0xC8, (byte)0xDB, (byte)0x7B, (byte)0x2A, 
                (byte)0xBD, (byte)0xBD, (byte)0xE5, (byte)0x39, 
                (byte)0x50, (byte)0xF4, (byte)0xC0, (byte)0xD2, 
                (byte)0x93, (byte)0xCD, (byte)0xD7, (byte)0x11, 
                (byte)0xA3, (byte)0x5B, (byte)0x67, (byte)0xFB, 
                (byte)0x14, (byte)0x99, (byte)0xAE, (byte)0x60, 
                (byte)0x03, (byte)0x86, (byte)0x14, (byte)0xF1, 
                (byte)0x39, (byte)0x4A, (byte)0xBF, (byte)0xA3, 
                (byte)0xB4, (byte)0xC8, (byte)0x50, (byte)0xD9, 
                (byte)0x27, (byte)0xE1, (byte)0xE7, (byte)0x76, 
                (byte)0x9C, (byte)0x8E, (byte)0xEC, (byte)0x2D, 
                (byte)0x19
            }), new Integer(new Math.BigInteger(1, new byte[] {
                (byte)0x03, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, 
                (byte)0xE6, (byte)0x61, (byte)0xCE, (byte)0x18, 
                (byte)0xFF, (byte)0x55, (byte)0x98, (byte)0x73, 
                (byte)0x08, (byte)0x05, (byte)0x9B, (byte)0x18, 
                (byte)0x68, (byte)0x23, (byte)0x85, (byte)0x1E, 
                (byte)0xC7, (byte)0xDD, (byte)0x9C, (byte)0xA1, 
                (byte)0x16, (byte)0x1D, (byte)0xE9, (byte)0x3D, 
                (byte)0x51, (byte)0x74, (byte)0xD6, (byte)0x6E, 
                (byte)0x83, (byte)0x82, (byte)0xE9, (byte)0xBB, 
                (byte)0x2F, (byte)0xE8, (byte)0x4E, (byte)0x47
            })), new Integer(0x02), null
        ); 
	    // таблица именованных параметров
	    private static readonly Dictionary<String, SpecifiedECDomain> set = 
		    new Dictionary<String, SpecifiedECDomain>(); 
	    static SpecifiedECDomain()
        {
            set.Add(ANSI.OID.x962_curves_c2pnb163v1, ECC2PNB163V1); 
            set.Add(ANSI.OID.x962_curves_c2pnb163v2, ECC2PNB163V2);
            set.Add(ANSI.OID.x962_curves_c2pnb163v3, ECC2PNB163V3);
            set.Add(ANSI.OID.x962_curves_c2pnb176w1, ECC2PNB176W1);
            set.Add(ANSI.OID.x962_curves_c2tnb191v1, ECC2TNB191V1);
            set.Add(ANSI.OID.x962_curves_c2tnb191v2, ECC2TNB191V2);
            set.Add(ANSI.OID.x962_curves_c2tnb191v3, ECC2TNB191V3);
            set.Add(ANSI.OID.x962_curves_c2onb191v4, ECC2ONB191V4);
            set.Add(ANSI.OID.x962_curves_c2onb191v5, ECC2ONB191V5);
            set.Add(ANSI.OID.x962_curves_c2pnb208w1, ECC2PNB208W1); 
            set.Add(ANSI.OID.x962_curves_c2tnb239v1, ECC2TNB239V1); 
            set.Add(ANSI.OID.x962_curves_c2tnb239v2, ECC2TNB239V2); 
            set.Add(ANSI.OID.x962_curves_c2tnb239v3, ECC2TNB239V3); 
            set.Add(ANSI.OID.x962_curves_c2onb239v4, ECC2ONB239V4); 
            set.Add(ANSI.OID.x962_curves_c2onb239v5, ECC2ONB239V5); 
            set.Add(ANSI.OID.x962_curves_c2pnb272w1, ECC2PNB272W1); 
            set.Add(ANSI.OID.x962_curves_c2pnb304w1, ECC2PNB304W1); 
            set.Add(ANSI.OID.x962_curves_c2tnb359v1, ECC2TNB359V1);
            set.Add(ANSI.OID.x962_curves_c2pnb368w1, ECC2PNB368W1);
            set.Add(ANSI.OID.x962_curves_c2tnb431r1, ECC2TNB431R1);
            set.Add(ANSI.OID.x962_curves_prime192v1, ECPRIME192V1);
            set.Add(ANSI.OID.x962_curves_prime192v2, ECPRIME192V2);
            set.Add(ANSI.OID.x962_curves_prime192v3, ECPRIME192V3);
            set.Add(ANSI.OID.x962_curves_prime239v1, ECPRIME239V1);
            set.Add(ANSI.OID.x962_curves_prime239v2, ECPRIME239V2);
            set.Add(ANSI.OID.x962_curves_prime239v3, ECPRIME239V3);
            set.Add(ANSI.OID.x962_curves_prime256v1, ECPRIME256V1); 
        
            set.Add(ANSI.OID.certicom_curves_secp112r1, ECSECP112R1); 
            set.Add(ANSI.OID.certicom_curves_secp112r2, ECSECP112R2); 
            set.Add(ANSI.OID.certicom_curves_secp128r1, ECSECP128R1); 
            set.Add(ANSI.OID.certicom_curves_secp128r2, ECSECP128R2); 
            set.Add(ANSI.OID.certicom_curves_secp160k1, ECSECP160K1); 
            set.Add(ANSI.OID.certicom_curves_secp160r1, ECSECP160R1); 
            set.Add(ANSI.OID.certicom_curves_secp160r2, ECSECP160R2); 
            set.Add(ANSI.OID.certicom_curves_secp192k1, ECSECP192K1); 
            set.Add(ANSI.OID.certicom_curves_secp224k1, ECSECP224K1); 
            set.Add(ANSI.OID.certicom_curves_secp224r1, ECSECP224R1); 
            set.Add(ANSI.OID.certicom_curves_secp256k1, ECSECP256K1); 
            set.Add(ANSI.OID.certicom_curves_secp384r1, ECSECP384R1); 
            set.Add(ANSI.OID.certicom_curves_secp521r1, ECSECP521R1); 
            set.Add(ANSI.OID.certicom_curves_sect113r1, ECSECT113R1); 
            set.Add(ANSI.OID.certicom_curves_sect113r2, ECSECT113R2); 
            set.Add(ANSI.OID.certicom_curves_sect131r1, ECSECT131R1); 
            set.Add(ANSI.OID.certicom_curves_sect131r2, ECSECT131R2); 
            set.Add(ANSI.OID.certicom_curves_sect163k1, ECSECT163K1); 
            set.Add(ANSI.OID.certicom_curves_sect163r1, ECSECT163R1); 
            set.Add(ANSI.OID.certicom_curves_sect163r2, ECSECT163R2); 
            set.Add(ANSI.OID.certicom_curves_sect193r1, ECSECT193R1); 
            set.Add(ANSI.OID.certicom_curves_sect193r2, ECSECT193R2); 
            set.Add(ANSI.OID.certicom_curves_sect233k1, ECSECT233K1); 
            set.Add(ANSI.OID.certicom_curves_sect233r1, ECSECT233R1); 
            set.Add(ANSI.OID.certicom_curves_sect239k1, ECSECT239K1); 
            set.Add(ANSI.OID.certicom_curves_sect283k1, ECSECT283K1); 
            set.Add(ANSI.OID.certicom_curves_sect283r1, ECSECT283R1); 
            set.Add(ANSI.OID.certicom_curves_sect409k1, ECSECT409K1); 
            set.Add(ANSI.OID.certicom_curves_sect409r1, ECSECT409R1); 
            set.Add(ANSI.OID.certicom_curves_sect571k1, ECSECT571K1); 
            set.Add(ANSI.OID.certicom_curves_sect571r1, ECSECT571R1); 
	    }
	    // получить именованные параметры
	    public static SpecifiedECDomain Parameters(String oid) { return set[oid]; } 
    }
}
