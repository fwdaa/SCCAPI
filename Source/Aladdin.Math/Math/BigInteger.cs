using System;
using System.Diagnostics;

namespace Aladdin.Math 
{
	///////////////////////////////////////////////////////////////////////////
	// ������� �����
	///////////////////////////////////////////////////////////////////////////
	[Serializable]
	public class BigInteger : IEquatable<BigInteger>
	{
		///////////////////////////////////////////////////////////////////////
		// �������� ������� ����� (���������� �������)
		///////////////////////////////////////////////////////////////////////
		private BigInteger(int sign, UInt32[] magnitude, bool check)
		{
			// ���������� ���� � ������ ��� �������� �����
            if (!check) { this.magnitude = magnitude; this.sign = sign; }
			else {
				// ��������� �� ������� �����
				if (magnitude.Length == 0) { this.magnitude = Utils.ZeroMagnitude; sign = 0; return; }

				// ��������� ������������� �������������� �������
                if (magnitude[0] != 0) { this.magnitude = magnitude; this.sign = sign; return; } 

				// ��� ���� ���� �������� �����
                for (int i = 1; i < magnitude.Length; ++i)
				{
					// ���������� ���������� �����
                    if (magnitude[i] == 0) continue; this.sign = sign;

					// �������� ����� ������ ��� ����
                    this.magnitude = new UInt32[magnitude.Length - i];

					// ����������� �������� �����
                    Array.Copy(magnitude, i, this.magnitude, 0, magnitude.Length - i); return;
				}
				// ����� �������
				this.magnitude = Utils.ZeroMagnitude; this.sign = 0; 
			}
		}
		// ������� �����
		private BigInteger() { magnitude = Utils.ZeroMagnitude; sign = 0; }

		// ���� ����� � ��� ����� � ������� big endian
        private int sign; private UInt32[] magnitude;

		///////////////////////////////////////////////////////////////////////
		// �������� ������� ����� �� �����
		///////////////////////////////////////////////////////////////////////
		public static readonly BigInteger Zero  = new BigInteger();

		// ������� ������ ������� �����
		public static readonly BigInteger One = new BigInteger(1, new UInt32[] {  1 }, false);
		public static readonly BigInteger Two = new BigInteger(1, new UInt32[] {  2 }, false);

		private static BigInteger ValueOf(UInt64 value)
		{
			switch (value)
            {
			// ������� ������
			case 0: return Zero; case 1: return One; case 2: return Two; 
            }
			// �������� ������� � ������� 32 ����
			UInt32 hi = (UInt32)((value >> 32) & UInt32.MaxValue); 
			UInt32 lo = (UInt32)((value >>  0) & UInt32.MaxValue); 

			// ������� ������� �����
            if (hi != 0) return new BigInteger(1, new UInt32[] { hi, lo }, false);
			else         return new BigInteger(1, new UInt32[] {     lo }, false);
		}

		public static BigInteger ValueOf(Int64 value)
		{
			// ������� ������������� �����
			if (value >= 0) return ValueOf((UInt64)value);

			// ������� ����������� ������������� �����
			if (value == Int64.MinValue) return ValueOf(~value).Not();

			// ������� ������������� �����
			return ValueOf(-value).Negate();
		}

        public static implicit operator BigInteger(UInt64 value)
        {
            // ������� ������� �����
            return BigInteger.ValueOf(value);
        }
        public static implicit operator BigInteger(Int64 value)
        {
			// ������� ������� �����
			return BigInteger.ValueOf(value);
		}

		///////////////////////////////////////////////////////////////////////
		// �������� �������� ����� �� ��� ��������� �������������
		///////////////////////////////////////////////////////////////////////
		public BigInteger(byte[] bytes) 
        {
			// ������������� ������ ���� � ������ ����
			magnitude = Utils.SBytesToUints(bytes, out sign); 
        }
		public BigInteger(int sign, byte[] bytes)
        {
			// ��������� �� ������� ����� 
			if (sign == 0) { magnitude = Utils.ZeroMagnitude; this.sign = 0; return; }

			// ������������� ������ ���� � ������ ����
			magnitude = Utils.UBytesToUints(bytes);

			// ���������� ���� �����
			this.sign = (magnitude.Length != 0) ? sign : 0; 
        }
		///////////////////////////////////////////////////////////////////////
		// �������������� � ������ ������
		///////////////////////////////////////////////////////////////////////
		public byte[] ToByteArray () { return Utils.UintsToBytes(sign, magnitude, false); }

		// ���������� ���� ����� � ��������
		public  int Signum    { get { return sign; } }
        public long LongValue { get 
        {
			// ��������� �� ������� �����
			if (sign == 0) return 0; 

			// ��������� ������ �����
			if (magnitude.Length > 2) throw new InvalidOperationException(); 

			// ��������� ������� �����
			ulong value = magnitude[magnitude.Length - 1];
		
			// ��� ������� ���� ����
			if (magnitude.Length > 1)
			{
				// ��������� ������ ������� �����
				value |= magnitude[magnitude.Length - 2] << 32; 
			}
			// ������ ���� �����
			return unchecked((sign < 0) ? -(long)value : (long)value);
		}}
        public int IntValue { get 
		{
			// ��������� �� ������� �����
			if (sign == 0) return 0; 

			// ��������� ������ �����
			if (magnitude.Length > 1) throw new InvalidOperationException(); 

			// ��������� ������� �����
			uint value = magnitude[magnitude.Length - 1];
		
			// ������ ���� �����
			return unchecked((sign < 0) ? -(int)value : (int)value);
		}}
		public static explicit operator Int64(BigInteger value)
		{
			// ������� ������� �����
			return value.LongValue;
		}
		public static explicit operator Int32(BigInteger value)
		{
			// ������� ������� �����
			return value.IntValue;
		}
		///////////////////////////////////////////////////////////////////////
		// �������������� �� ���������� ���
		///////////////////////////////////////////////////////////////////////
#if !NO_NUMERICS
        private static BigInteger FromNumericInteger(System.Numerics.BigInteger value)
        {
			// �������� �������� �������������
			byte[] bytes = value.ToByteArray(); Array.Reverse(bytes);

            // ������� ������� �����
            return new BigInteger(bytes); 
        }
        private static System.Numerics.BigInteger ToNumericInteger(BigInteger value)
        {
			// �������� �������� �������������
			byte[] bytes = value.ToByteArray(); Array.Reverse(bytes);
            
            // ������� ������� �����
            return new System.Numerics.BigInteger(bytes); 
        }
#endif 
		///////////////////////////////////////////////////////////////////////
		// ��������� ��������� �������� �����
		///////////////////////////////////////////////////////////////////////
		public BigInteger(int bits, Random rand)
		{
			// ��������� �� ������� ����� 
			if (bits == 0) { magnitude = Utils.ZeroMagnitude; sign = 0; return; }

			// ������������� ��������� ������
			byte[] buffer = new byte[(bits + 7) / 8]; rand.NextBytes(buffer);

			// ���������� �� ������ �����
			buffer[0] &= (byte)(Byte.MaxValue >> (8 * buffer.Length - bits));

			// ������������� ������ ���� � ������ ����
			magnitude = Utils.UBytesToUints(buffer);

			// ���������� ���� �����
			sign = (magnitude.Length != 0) ? 1 : 0;
		}

		public BigInteger(int bits, int certainty, Random rand)
		{
			// ��������� ������������ ������
            Debug.Assert(bits >= 2); sign = 1; 

			// �������� ������ ��� �������� �����
			byte[] buffer = new byte[(bits + 7) / 8]; 

            // ������������� ��������� ������
            if (bits == 2) { rand.NextBytes(buffer); 

				// ���������� �������� �������� �����
				if ((buffer[0] & 1) == 0) magnitude = Two.magnitude;

				// ���������� �������� �������� �����
				else magnitude = new UInt32[] { 3 }; return; 
			}
			// ���������� ����� ���������� �����
			int unused = 8 * buffer.Length - bits;
			for (;;)
			{
				// ������������� ��������� ������
				rand.NextBytes(buffer); buffer[0] &= (byte)(Byte.MaxValue >> unused);

				// ���������� ������� � ������� ����
				buffer[0] |= (byte)(1 << (7 - unused)); buffer[buffer.Length - 1] |= 1;

				// ������������� ������ ���� � ������ ����
				magnitude = Utils.UBytesToUints(buffer);

				// ��������� �� �������� � ��������� ������������
				if (certainty < 1 || CheckProbablePrime(certainty, rand)) break;

				// ���� ����� ����� 32 ����� 
				if (magnitude.Length >= 2)
				{
					// ��������� 10000 �������
					for (int rep = 0; rep < 10000; rep++)
					{
						// ������������� ��������� ��������
						int offset = rand.Next(1, magnitude.Length);

						// ������������� ��� ��������� �����
						UInt32 value1 = unchecked((UInt32)(rand.Next() << 1));
						UInt32 value2 = unchecked((UInt32)(rand.Next() << 1));

						// �������� ��������� ����� � ����� �� ���������� ��������
						magnitude[magnitude.Length - offset] ^= value1;
						magnitude[magnitude.Length -      1] ^= value2;

						// ��������� �� �������� � ��������� ������������
						if (CheckProbablePrime(certainty, rand)) return;
					}
				}
			}
		}
		///////////////////////////////////////////////////////////////////////
		// �������������� ������
		///////////////////////////////////////////////////////////////////////
		public static bool operator == (BigInteger A, BigInteger B)
		{
			// �������� ��� �����
			return ((object)A != null) ? A.Equals(B) : ((object)B == null);
		}
		public static bool operator != (BigInteger A, BigInteger B)
		{
			// �������� ��� �����
			return ((object)A != null) ? !A.Equals(B) : ((object)B != null);
		}
		public bool Equals(BigInteger other)
		{
			// ��������� �� ���������
			if (Object.ReferenceEquals(other, this)) return true;
			if (other == null) return false;

			// ��������� ���� �����
			if (other.sign != sign) return false;

			// ��������� ������ �������
			if (other.magnitude.Length != magnitude.Length) return false;

			// ��� ���� ���� �������
			for (int i = 0; i < magnitude.Length; i++)
			{
				// ��������� ���������� ����� �������
				if (other.magnitude[i] != magnitude[i]) return false;
			}
			return true;
		}
		public override bool Equals(object obj)
		{
			// ������������� ��� �������
			BigInteger other = obj as BigInteger;

			// �������� ��� �����
			return (other != null) ? Equals(other) : false;
		}
		public override int GetHashCode()
		{
			// ������ ������ �����
			uint hc = (uint) magnitude.Length; if (hc == 0) return (int)hc; 

			// ������ ������ �����
			hc ^= magnitude[0]; if (magnitude.Length > 1)
			{
				// ������ ��������� �����
                hc ^= magnitude[magnitude.Length - 1];
			}
			// ������ ���� �����
			return unchecked((int)((sign < 0) ? ~hc : hc));
		}
		///////////////////////////////////////////////////////////////////////
		// ��������� ������� �����
		///////////////////////////////////////////////////////////////////////
		public static bool operator <(BigInteger A, BigInteger B)
		{
			// �������� ��� �����
			return A.CompareTo(B) < 0;
		}
		public static bool operator >(BigInteger A, BigInteger B)
		{
			// �������� ��� �����
			return A.CompareTo(B) > 0;
		}
		public static bool operator <=(BigInteger A, BigInteger B)
		{
			// �������� ��� �����
			return A.CompareTo(B) <= 0;
		}
		public static bool operator >=(BigInteger A, BigInteger B)
		{
			// �������� ��� �����
			return A.CompareTo(B) >= 0;
		}
		public int CompareTo(object obj) { return CompareTo((BigInteger)obj); }

		public int CompareTo(BigInteger other)
		{
			// �������� ����� ������� �����
			if (sign < other.sign) return -1;
			if (sign > other.sign) return  1; 

			// �������� ������� �����
			if (sign == 0) return 0; 

			// �������� ����� ������ �����
			return sign * Utils.Compare(magnitude, 0, other.magnitude, 0); 
		}
		public BigInteger Max(BigInteger value)
		{
			return CompareTo(value) > 0 ? this : value;
		}
		public BigInteger Min(BigInteger value)
		{
			return CompareTo(value) < 0 ? this : value;
		}

		///////////////////////////////////////////////////////////////////////
		// ������� ��������
		///////////////////////////////////////////////////////////////////////
		public int BitCount { get 
		{
			// ���������� ������������� �����
			if (sign < 0) return BitLength - Not().BitCount;

			// ���������� ������������� �����
			return Utils.BitCount(magnitude, 0, magnitude.Length); 
		}}
		public int BitLength { get 
		{
			// ������� ����������� �����
			return Utils.BitLength(sign, magnitude, 0, magnitude.Length);
		}}
		///////////////////////////////////////////////////////////////////////
		// �������� � ������
		///////////////////////////////////////////////////////////////////////
		public bool TestBit(int n)
		{
			// ���������� ������������� �����
			Debug.Assert(n >= 0); if (sign < 0) return !Not().TestBit(n);

			// ���������� ������� �����
			int i = n / 32; if (i >= magnitude.Length) return false;

			// ��������� ��������� ���������� ����
			return ((magnitude[magnitude.Length - i - 1] >> (n % 32)) & 1) > 0;
		}
		public BigInteger FlipBit(int n)
		{
            // ���������� ��������������� ����� ��� �������������� ���
            if (sign <= 0 || n >= BitLength - 1) return Xor(One.ShiftLeft(n));

            // ������� ����� ������� ����
            Debug.Assert(n >= 0); UInt32[] magCopy = (UInt32[])magnitude.Clone();

            // �������� ��������� ��� � ����� �������
			magCopy[magCopy.Length - 1 - (n >> 5)] ^= 1U << (n & 31);

            // ������� ����� ������� �����
			return new BigInteger(sign, magCopy, false);
        }
		public BigInteger SetBit(int n)
		{
			// ��������� ��������� ���������� ����
			Debug.Assert(n >= 0); if (TestBit(n)) return this;

            // ���������� ��������������� ����� ��� �������������� ���
            if (sign <= 0 || n >= BitLength - 1) return Or(One.ShiftLeft(n));

            // ������� ����� ������� ����
			UInt32[] magCopy = (UInt32[])magnitude.Clone();

            // �������� ��������� ��� � ����� �������
			magCopy[magCopy.Length - 1 - (n >> 5)] ^= 1U << (n & 31);

            // ������� ����� ������� �����
			return new BigInteger(sign, magCopy, false);
        }
		public BigInteger ClearBit(int n)
		{
			// ��������� ����� ���������� ����
			Debug.Assert(n >= 0); if (!TestBit(n)) return this;

            // ���������� ��������������� ����� ��� �������������� ���
            if (sign <= 0 || n >= BitLength - 1) return And(One.ShiftLeft(n).Not());

            // ������� ����� ������� ����
			UInt32[] magCopy = (UInt32[])magnitude.Clone();

            // �������� ��������� ��� � ����� �������
			magCopy[magCopy.Length - 1 - (n >> 5)] ^= 1U << (n & 31);

            // ������� ����� ������� �����
			return new BigInteger(sign, magCopy, false);
        }
		///////////////////////////////////////////////////////////////////////
		// ���������� ��������
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator ~(BigInteger A)				{ return A.Not( ); }
		public static BigInteger operator &(BigInteger A, BigInteger B) { return A.And(B); }
		public static BigInteger operator |(BigInteger A, BigInteger B) { return A.Or (B); }
		public static BigInteger operator ^(BigInteger A, BigInteger B) { return A.Xor(B); }

		public BigInteger Not() { return Increment().Negate(); }

		public BigInteger And(BigInteger B)
		{
			// ��������� �� �������� � �����
			if (sign == 0 || B.sign == 0) return Zero; 

			// ���������� ������� ���� � ������ ���������� ����������
			UInt32[] magA =   sign > 0 ?   magnitude :   Add(One).magnitude;
			UInt32[] magB = B.sign > 0 ? B.magnitude : B.Add(One).magnitude;

			// �������� ������ ���������� �������
			UInt32[] magC = new UInt32[System.Math.Max(magA.Length, magB.Length)];

			// ���������� ��������� �������
			int startA = magC.Length - magA.Length;
			int startB = magC.Length - magB.Length;

			// ���������� ���� ����������
			bool negC = sign < 0 && B.sign < 0;

			// ��� ���� ���� ����������
			for (int i = 0; i < magC.Length; ++i)
			{
				// ������� ��������� �����
				UInt32 a = (i >= startA) ? magA[i - startA] : 0;
				UInt32 b = (i >= startB) ? magB[i - startB] : 0;

				// ��� ������������� ��������� �����
				if (sign < 0) a = ~a; if (B.sign < 0) b = ~b;

				// ��������� ���������� ��������
				magC[i] = a & b; if (negC) magC[i] = ~magC[i];
			}
			// ������� ������� ����� ��� ����������
			BigInteger C = new BigInteger(1, magC, true);

			// ���������� ���� �����
			if (negC) C = C.Not(); return C;
		}

		public BigInteger Or(BigInteger B)
		{
			// ��������� �� �������� � �����
			if (sign == 0) return B; if (B.sign == 0) return this; 

			// ���������� ������� ���� � ������ ���������� ����������
			UInt32[] magA =   sign > 0 ?   magnitude :   Add(One).magnitude;
			UInt32[] magB = B.sign > 0 ? B.magnitude : B.Add(One).magnitude;

			// �������� ������ ���������� �������
			UInt32[] magC = new UInt32[System.Math.Max(magA.Length, magB.Length)];

			// ���������� ��������� �������
			int startA = magC.Length - magA.Length;
			int startB = magC.Length - magB.Length;

			// ���������� ���� ����������
			bool negC = sign < 0 || B.sign < 0;

			// ��� ���� ���� ����������
			for (int i = 0; i < magC.Length; ++i)
			{
				// ������� ��������� �����
				UInt32 a = (i >= startA) ? magA[i - startA] : 0;
				UInt32 b = (i >= startB) ? magB[i - startB] : 0;

				// ��� ������������� ��������� �����
				if (sign < 0) a = ~a; if (B.sign < 0) b = ~b;

				// ��������� ���������� ��������
				magC[i] = a | b; if (negC) magC[i] = ~magC[i];
			}
			// ������� ������� ����� ��� ����������
			BigInteger C = new BigInteger(1, magC, true);

			// ���������� ���� �����
			if (negC) C = C.Not(); return C;
		}

		public BigInteger Xor(BigInteger B)
		{
			// ��������� �� �������� � �����
			if (sign == 0) return B; if (B.sign == 0) return this; 

			// ���������� ������� ���� � ������ ���������� ����������
			UInt32[] magA =   sign > 0 ?   magnitude :   Add(One).magnitude;
			UInt32[] magB = B.sign > 0 ? B.magnitude : B.Add(One).magnitude;

			// �������� ������ ���������� �������
			UInt32[] magC = new UInt32[System.Math.Max(magA.Length, magB.Length)];

			// ���������� ��������� �������
			int startA = magC.Length - magA.Length;
			int startB = magC.Length - magB.Length;

			// ���������� ���� ����������
			bool negC = (sign != B.sign);

			// ��� ���� ���� ����������
			for (int i = 0; i < magC.Length; ++i)
			{
				// ������� ��������� �����
				UInt32 a = (i >= startA) ? magA[i - startA] : 0;
				UInt32 b = (i >= startB) ? magB[i - startB] : 0;

				// ��� ������������� ��������� �����
				if (sign < 0) a = ~a; if (B.sign < 0) b = ~b;

				// ��������� ���������� ��������
				magC[i] = a ^ b; if (negC) magC[i] = ~magC[i];
			}
			// ������� ������� ����� ��� ����������
			BigInteger C = new BigInteger(1, magC, true);

			// ���������� ���� �����
			if (negC) C = C.Not(); return C;
		}
		///////////////////////////////////////////////////////////////////////
		// ���������� ������
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator <<(BigInteger A, int n) { return A.ShiftLeft (n); }
		public static BigInteger operator >>(BigInteger A, int n) { return A.ShiftRight(n); }

		public BigInteger ShiftLeft(int n)
		{
			// ��������� �� ������� ����� � �����
			if (sign == 0) return Zero; if (n == 0) return this; 

			// ��������� �� ������������� �����
			if (n < 0) return ShiftRight(-n); 

			// ��������� ����� �����
			UInt32[] mag = Utils.ShiftLeft(magnitude, 0, n);

			// �������� ��������� ������
			return new BigInteger(sign, mag, true);
		}

		public BigInteger ShiftRight(int n)
		{
			// ��������� �� ������� � ������������� �����
			if (n == 0) return this; if (n < 0) return ShiftLeft(-n);

			// ��������� �� �����, ����������� �����������
			if (n >= BitLength) return (sign < 0) ? One.Negate() : Zero;

			// ���������� ������������� �����
			if (sign < 0) return Not().ShiftRight(n).Not(); 

			// ������� ����� �������
			UInt32[] mag = (UInt32[]) magnitude.Clone();

			// ��������� ����� ������
			Utils.ShiftRight(mag, 0, n); return new BigInteger(1, mag, true);
		}
		///////////////////////////////////////////////////////////////////////
		// ��������� ����� �����
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator -(BigInteger A) { return A.Negate(); }

		public BigInteger Abs   () { return (sign >= 0) ? this : Negate(); }
        public BigInteger Negate()
		{
			// �������� ���� �����
			return (sign != 0) ? new BigInteger(-sign, magnitude, false) : this;
		}
		///////////////////////////////////////////////////////////////////////
		// ��������� � ���������
		///////////////////////////////////////////////////////////////////////
		public BigInteger Increment()
		{
			// ��������� �� ������� �����
			if (sign == 0) return One;

			// ����������� ������ �����
			UInt32[] magCopy = (UInt32[])magnitude.Clone();

			// ��� �������������� �����
			if (sign > 0)
			{
				// �������� ������� � ������
				Utils.AddTo(magCopy, One.magnitude);

				// ������� ��������� ��������
				return new BigInteger(1, magCopy, true);
			}
			else {
				// ������� ������� �� ������
				Utils.SubtractFrom(magCopy, One.magnitude, 0);

				// ������� ��������� ���������
				return new BigInteger(-1, magCopy, true);
			}
		}
		public BigInteger Decrement()
		{
			// ��������� �� ������� �����
			if (sign == 0) return One.Negate();

			// ����������� ������ �����
			UInt32[] magCopy = (UInt32[])magnitude.Clone();

			// ��� �������������� �����
			if (sign > 0)
			{
				// ������� ������� �� ������
				Utils.SubtractFrom(magCopy, One.magnitude, 0);

				// ������� ��������� ���������
				return new BigInteger(1, magCopy, true);
			}
			else {
				// �������� ������� � ������
				Utils.AddTo(magCopy, One.magnitude);

				// ������� ��������� ��������
				return new BigInteger(-1, magCopy, true);
			}
		}
		///////////////////////////////////////////////////////////////////////
		// �������� � ���������
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator +(BigInteger A, BigInteger B) { return A.Add     (B); }
		public static BigInteger operator -(BigInteger A, BigInteger B) { return A.Subtract(B); }

		public BigInteger Add(BigInteger B)
		{
			// ��������� �� �������� � �����
			if (sign == 0) return B; if (B.sign == 0) return this;

			// ��� ����� ������� �����
			if (sign != B.sign)
			{
				// ������� �� ������� ����� ������
				if (B.sign < 0) return Subtract(B.Negate());

				// ������� �� ������� ����� ������
				else return B.Subtract(Negate());
			}
			// ���������� ������� � ������� �����
			UInt32[] big = magnitude; UInt32[] small = B.magnitude;

			// ���������� ������� � ������� �����
			if (magnitude.Length < B.magnitude.Length)
			{
				big = B.magnitude; small = magnitude;
			}
			// �������������� ������� �����
			UInt32[] bigCopy = new UInt32[big.Length + 1];

			// �������� � �������� ����� �������
			big.CopyTo(bigCopy, 1); Utils.AddTo(bigCopy, small);

			// ������� ��������� ��������
			return new BigInteger(sign, bigCopy, true);
		}

		public BigInteger Subtract(BigInteger B)
		{
			// ��������� �� ��������� ����
			if (B.sign == 0) return this; if (sign == 0) return B.Negate();

			// ��� ������������ ������ ������� � ��������
			if (sign != B.sign) return Add(B.Negate());

			// �������� ���������� ��������
			int compare = Utils.Compare(magnitude, 0, B.magnitude, 0);

			// ��� ���������� ������� ����
			if (compare == 0) return Zero;

			// ���������� ������� � ������� �����
			UInt32[] big   = (compare < 0) ? B.magnitude : magnitude; 
			UInt32[] small = (compare > 0) ? B.magnitude : magnitude; 

			// ����������� ������� �����
			UInt32[] bigCopy = (UInt32[]) big.Clone();

			// ������� ������� ����� �� ��������
			Utils.SubtractFrom(bigCopy, small, 0); 
			
			// ������� ��������� ���������
			return new BigInteger(sign * compare, bigCopy, true);
		}
		///////////////////////////////////////////////////////////////////////
		// ��������� � ���������� � �������
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator *(BigInteger A, BigInteger B) { return A.Multiply(B); }

		private BigInteger MultiplyImpl(BigInteger B)
		{
			// ���������� ��������� �� ����
			if (sign == 0 || B.sign == 0) return Zero;

			// ���������� ��������� �� �������
			if (B.Equals(One)) return this; if (Equals(One)) return B;

			// �������� ������ ��� ������������
			UInt32[] magC = new UInt32[magnitude.Length + B.magnitude.Length];

			// ���������� ����������� ��������
			if (B == this) Utils.Square(magnitude, magC);

			// ���������� ������������� ��������
			else Utils.Multiply(magnitude, B.magnitude, magC);

			// ������� ��������� ������������
			return new BigInteger(sign * B.sign, magC, true);
		}
		public BigInteger Multiply(BigInteger B)
		{
#if !NO_NUMERICS
            // ��������� ��������������� ����
            System.Numerics.BigInteger self  = ToNumericInteger(this);
            System.Numerics.BigInteger other = ToNumericInteger(B   );

            // ��������� ���������
            BigInteger result = FromNumericInteger(
                System.Numerics.BigInteger.Multiply(self, other)
            );  
#if NUMERICS_CHECK
            // ��������� ���������� ����������
            Debug.Assert(result == MultiplyImpl(B)); 
#endif             
            return result; 
#else
            // ��������� ���������
            return MultiplyImpl(B); 
#endif 
		}
		private BigInteger PowImpl(int exp)
		{
			// ���������� ������� �������
			Debug.Assert(exp >= 0); if (exp == 0) return One;

			// ���������� ������� �������� � �������
			if (sign == 0 || Equals(One)) return this;

			// ������ ��������� ��������
			BigInteger result = One; BigInteger power = this;

			while (true)
			{
				// �������� �� ������� 2 �������
				if ((exp & 1) != 0) result = result.Multiply(power);

				// ��������� �� ���������� ���������
				exp >>= 1; if (exp == 0) break;

				// ��������� ������� 2 �������
				power = power.Multiply(power);
			}
			return result;
		}
		public BigInteger Pow(int exp)
		{
#if !NO_NUMERICS
            // ��������� ��������������� ����
            System.Numerics.BigInteger self  = ToNumericInteger(this);

            // ��������� ���������� � �������
            BigInteger result = FromNumericInteger(
                System.Numerics.BigInteger.Pow(self, exp)
            ); 
#if NUMERICS_CHECK
            // ��������� ���������� ����������
            Debug.Assert(result == PowImpl(exp)); 
#endif 
            return result; 
#else 
            // ��������� ���������� � �������
            return PowImpl(exp); 
#endif 
		}
		///////////////////////////////////////////////////////////////////////
		// ������� � ������� �� �������
		///////////////////////////////////////////////////////////////////////
		public static BigInteger operator /(BigInteger A, BigInteger B) { return A.Divide   (B); }
		public static BigInteger operator %(BigInteger A, BigInteger B) { return A.Remainder(B); }

		private BigInteger[] DivideAndRemainderImpl(BigInteger B)
		{
			// �������� ������ ��� ������������ �����
			Debug.Assert(B.sign != 0); BigInteger[] biggies = new BigInteger[2];

			// ���������� ������� �����
			if (sign == 0) { biggies[0] = Zero; biggies[1] = Zero; return biggies; }

			// ����������� �������
			UInt32[] remainder = (UInt32[])magnitude.Clone();

			// ��������� ������� � �������
			UInt32[] quotient = Utils.Divide(remainder, B.magnitude);

			// ������� ������� 
			biggies[0] = new BigInteger(sign * B.sign, quotient, true);

			// ������� �������
			biggies[1] = new BigInteger(sign, remainder, true);	return biggies;
		}
		public BigInteger[] DivideAndRemainder(BigInteger B)
		{
#if !NO_NUMERICS
			// �������� ������ ��� ������������ �����
			Debug.Assert(B.sign != 0); BigInteger[] biggies = new BigInteger[2];

            // ��������� ��������������� ����
            System.Numerics.BigInteger self  = ToNumericInteger(this);
            System.Numerics.BigInteger other = ToNumericInteger(B   );

			// ��������� ������� � �������
            System.Numerics.BigInteger remainder; 
			System.Numerics.BigInteger quotient = 
                System.Numerics.BigInteger.DivRem(self, other, out remainder
            );
            // ��������� ��������������� ����
            biggies[0] = FromNumericInteger(quotient ); 
            biggies[1] = FromNumericInteger(remainder); 
#if NUMERICS_CHECK
            // ��������� ���������� ����������
            Debug.Assert(biggies[0] == DivideImpl   (B)); 
            Debug.Assert(biggies[1] == RemainderImpl(B)); 
#endif 
            return biggies; 
#else 
            // ��������� ������� � �������
            return DivideAndRemainderImpl(B); 
#endif 
		}
		private BigInteger DivideImpl(BigInteger B)
		{
			// ���������� ������� �����
			Debug.Assert(B.sign != 0); if (sign == 0) return Zero;

			// ����������� �������
			UInt32[] remainder = (UInt32[])magnitude.Clone();

			// ��������� ������� � �������
			UInt32[] quotient = Utils.Divide(remainder, B.magnitude);

			// ������� ������� 
			return new BigInteger(sign * B.sign, quotient, true);
		}
		public BigInteger Divide(BigInteger B)
		{
#if !NO_NUMERICS
            // ��������� ��������������� ����
            System.Numerics.BigInteger self  = ToNumericInteger(this);
            System.Numerics.BigInteger other = ToNumericInteger(B   );

			// ��������� ������� 
            BigInteger result = FromNumericInteger(
                System.Numerics.BigInteger.Divide(self, other)
            );
#if NUMERICS_CHECK
            // ��������� ���������� ����������
            Debug.Assert(result == DivideImpl(B)); 
#endif 
            return result; 
#else
			// ������� ������� 
            return DivideImpl(B); 
#endif 
		}
		private BigInteger RemainderImpl(BigInteger B)
		{
			// ���������� ������� �����
			Debug.Assert(B.sign != 0); if (sign == 0) return Zero;

			// ��� ������ ������
			if (B.magnitude.Length > 1)
			{
				// �������� ������� � �������� 
				if (Utils.Compare(magnitude, 0, B.magnitude, 0) < 0) return this;

				// ����������� �������
				UInt32[] remainder = (UInt32[])magnitude.Clone();

				// ��������� ������� �� �������
				Utils.Remainder(remainder, B.magnitude);

				// ������� ���������� ���������
				return new BigInteger(sign, remainder, true);  
			}
			else {
				// ���������� ������� �� �������
				if (B.magnitude[0] == 1) return Zero;

				// ��������� ������� �� �������
				UInt32 remainder = Utils.Remainder(magnitude, B.magnitude[0]);

				// ��������� �� ������� ���������
				if (remainder == 0) return Zero; 

				// ������� ���������� ���������
				return new BigInteger(sign, new UInt32[] { remainder }, false);  
			}
        }
		public BigInteger Remainder(BigInteger B)
		{
#if !NO_NUMERICS
            // ��������� ��������������� ����
            System.Numerics.BigInteger self  = ToNumericInteger(this);
            System.Numerics.BigInteger other = ToNumericInteger(B   );

			// ��������� �������
			BigInteger result = FromNumericInteger(
                System.Numerics.BigInteger.Remainder(self, other)
            );
#if NUMERICS_CHECK
            // ��������� ���������� ����������
            Debug.Assert(result == RemainderImpl(B)); 
#endif 
            return result; 
#else 
			// ������� �������
            return RemainderImpl(B); 
#endif 
		}
 		///////////////////////////////////////////////////////////////////////
		// ���������� ����������
		///////////////////////////////////////////////////////////////////////
		public BigInteger Mod(BigInteger P)
		{
			// ��������� ������� �� �������
			Debug.Assert(P.sign > 0); BigInteger remainder = Remainder(P);

			// ������� ������� �� �������
			return (remainder.sign >= 0) ? remainder : remainder.Add(P);
		}
		public BigInteger ModInverse(BigInteger P)
		{
			// ��������� ������������ ������
			Debug.Assert(P.sign > 0);   

			// ��������� ����������� �������� �������
			BigInteger[] result = Z.Ring.Instance.Euclid(Mod(P), P);

			// ��������� ������������ ��������
			if (!result[0].Equals(One)) throw new ArithmeticException("GCD != 1");

			// ������� �������� �������
			return (result[1].sign >= 0) ? result[1] : result[1].Add(P);
		}
		private BigInteger ModPowOddImpl(BigInteger E, BigInteger P)
		{
			// ��������� �� ��������� ������
			if (P.Equals(BigInteger.One)) return BigInteger.Zero;

			// ��������� �� ������� ��������
			if (sign   == 0) return BigInteger.Zero;
			if (E.sign == 0) return BigInteger.One;

            // ������� ������ ����������
            Fp.MontGroup group = new Fp.MontGroup(P); 

			// ��������� R = this * 2^{32n} mod P
			BigInteger R = ShiftLeft(32 * P.magnitude.Length).Mod(P);

			// ��������� R^E (mod P) �� ����������
			R = group.Power(R, E.Abs());

			// �������� �� ������� �� ����������
			R = group.Product(R, One);

			// ������ ���� ����������
			return E.sign > 0 ? R : R.ModInverse(P);
		}
		private BigInteger ModPowImpl(BigInteger E, BigInteger P)
		{
			// ��������� ������������ ��������
			Debug.Assert(sign >= 0 && CompareTo(P) < 0 && P.sign > 0); 

			// ��� ��������� ������ 
			if ((P.magnitude[P.magnitude.Length - 1] & 1) != 0) 
            {
                // �������� ����� � �������
                return ModPowOddImpl(E, P);
            }
			// ��������� �� ������� ��������
			if (sign   == 0) return BigInteger.Zero;
			if (E.sign == 0) return BigInteger.One;

			// �������� ������ ��� ���������� 
			UInt32[] A = new UInt32[P.magnitude.Length];

			// ������ ��������� �������
			magnitude.CopyTo(A, A.Length - magnitude.Length);

			// �������� ��������������� �����
			UInt32[] T = new UInt32[P.magnitude.Length * 2];

			// ��������� ������� ������ ���������� �������
			UInt32 v = E.magnitude[0]; int bits = 0;

			// ��������� ������� ��� ���������� ������� 
			for (; (v & Int32.MinValue) == 0; v <<= 1, bits++) ; v <<= 1; bits++;

			// ��� ���� �������� ���������� �������
			for (int i = 0; i < E.magnitude.Length; i++)
			{
				// ��������� ��������� ������ ���������� �������
				if (i > 0) { v = E.magnitude[i]; bits = 0; }

				// ��� ���� ����� ���������� �������
				for (; v != 0; v <<= 1, bits++)
				{
					// �������� ��������� � ������� �� ������
					Utils.Square(A, T); Utils.Remainder(T, P.magnitude);
					Array.Copy(T, T.Length - A.Length, A, 0, A.Length);

					// ��� ���������� ���� ���������� �������
					if ((v & Int32.MinValue) != 0)
					{
						// �������� �� �������� ����� �� ������
						Utils.Multiply(A, magnitude, T); Utils.Remainder(T, P.magnitude);
						Array.Copy(T, T.Length - A.Length, A, 0, A.Length);
					}
				}
				// ��� ������� ����� ���������� �������
				for (; bits < 32; bits++)
				{
					// �������� ��������� � ������� �� ������
					Utils.Square(A, T); Utils.Remainder(T, P.magnitude);
					Array.Copy(T, T.Length - A.Length, A, 0, A.Length);
				}
			}
			// ���������� �� ���������� �����
			BigInteger R = new BigInteger(1, A, true);

			// ������ ���� ����������
			return E.sign > 0 ? R : R.ModInverse(P);
		}
		public BigInteger ModPow(BigInteger E, BigInteger P)
		{
			// ��������� ������������ ��������
			Debug.Assert(sign >= 0 && CompareTo(P) < 0 && P.sign > 0); 
#if !NO_NUMERICS
            // ��������� ��������������� ����
            System.Numerics.BigInteger self    = ToNumericInteger(this);
            System.Numerics.BigInteger exp     = ToNumericInteger(E   );
            System.Numerics.BigInteger modulus = ToNumericInteger(P   );

			// ��������� ���������� � �������
			BigInteger result = FromNumericInteger(
                System.Numerics.BigInteger.ModPow(self, exp, modulus)
            );
#if NUMERICS_CHECK
            // ��������� ���������� ����������
            Debug.Assert(result == ModPowImpl(E, P)); 
#endif 
            return result; 
#else 
			// ��������� ���������� � �������
            return ModPowImpl(E, P); 
#endif 
		}
		///////////////////////////////////////////////////////////////////////
		// �������� �������� �����
		///////////////////////////////////////////////////////////////////////
		public bool IsProbablePrime(int certainty, Random rand)
		{
			// ��������� ������������� ��������
			if (certainty <= 0) return true; BigInteger A = Abs();

			// ������ ����� �������� �������, ���� ����� 2
			if (!A.TestBit(0)) return A.Equals(Two);

			// ������� �� �������� ������� ������
			if (A.Equals(One)) return false;

			// ��������� ����� �� ��������
			return A.CheckProbablePrime(certainty, rand);
		}
		private bool CheckProbablePrime(int certainty, Random rand)
		{
			// ��������� �� �������� ��������� �����
			if (magnitude.Length == 1) return Utils.IsPrime(magnitude[0]);  

			// ��������� N - 1
			BigInteger N1 = Subtract(One); int S = 0; 

			// ����� ������� ��������� ������ ����� N-1
			for (int i = N1.magnitude.Length - 1; i >= 0; i--)
			{
				// ���������� ������� ������
				if (N1.magnitude[i] == 0) continue; UInt32 mask = 1; 

				// ����� ����� �� ����������� ���������� �������
				int bitLength = 32 * (N1.magnitude.Length - 1 - i);

				// ��� ���� ����� ���������� �������
				for (int j = 0; j < 32; j++, mask <<= 1)
				{
					// ����� ������� ��������� ���
					if ((N1.magnitude[i] & mask) != 0)
					{
						S = bitLength + j; break; 
					}
				}
				break; 
			}
			// ��������� R = (N - 1) / 2^S
			BigInteger R = N1.ShiftRight(S); int bits = BitLength; 

			// � ��������� ������������
			for (BigInteger A; certainty > 0; certainty -= 2)
			{
				// ������������� ��������� �����
				do { A = new BigInteger(bits, rand); }

				// � ��������� �� 2 �� N - 2 
				while (A.CompareTo(One) <= 0 || A.CompareTo(N1) >= 0);

				// ��������� Y = A^R mod N
				BigInteger Y = A.ModPow(R, this);

				// ��������� �� �������
				if (Y.Equals(One)) continue; int j = 0;

				// ���� Y �� ����� N-1
				while (!Y.Equals(N1))
				{
					// ��������� �� ����������
					if (++j == S) return false;

					// ��������� Y^{2^j} mod N
					Y = Y.ModPow(Two, this);

					// ��������� �� �������
					if (Y.Equals(One)) return false;
				}
			}
			return true;
		}
	}
}
