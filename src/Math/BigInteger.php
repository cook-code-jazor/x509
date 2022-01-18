<?php
namespace Jazor\Math;

use GMP;

/**
 * convert from BouncyCastle
 */
class BigInteger implements IBigInteger
{
    private static bool $initialized = false;

    public static BigInteger $Zero;
    public static BigInteger $One;
    public static BigInteger $Two;
    public static BigInteger $Three;
    public static BigInteger $Four;
    public static BigInteger $Ten;

    /**
     * @throws \Exception
     */
    public static function staticInitialize()
    {
        if (self::$initialized) return;
        self::$initialized = true;
        self::$Zero = new static(0, "\x00");
        self::$One = new static(gmp_init(1));
        self::$Two = new static(gmp_init(2));
        self::$Three = new static(gmp_init(3));
        self::$Four = new static(gmp_init(4));
        self::$Ten = new static(gmp_init(10));

    }

    private int $sign;

    private ?GMP $calculator = null;

    /**
     * <p>new <font color="#FF4F19">BigInteger2</font>(<b>int</b> $sign, <b>string</b> $binary);</p>
     * <p>new <font color="#FF4F19">BigInteger2</font>(<b>string</b> $binary);</p>
     * <p>new <font color="#FF4F19">BigInteger2</font>(<b>GMP</b> $gmp);</p>
     * @param string|int|GMP $sign
     * @param string|null $binary
     * @throws \Exception
     */
    public function __construct($sign, $binary = null)
    {
        self::staticInitialize();
        if (is_string($sign)) {
            $this->sign = self::checkBinary($binary, $outBytes);
            if (strlen($outBytes) == 0) {
                $this->calculator = gmp_init(0);
                $this->sign = 0;
                return;
            }
            $gmp = gmp_import($outBytes, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

            $this->calculator = $this->sign < 0 ? -$gmp : $gmp;
            return;
        }

        if ($sign instanceof GMP) {
            $this->sign = gmp_sign($sign);
            $this->calculator = $sign;
            return;
        }

        if (!is_int($sign) || $sign > 1 || $sign < -1) throw new \InvalidArgumentException('sign must be integer');

        $this->sign = $sign;
        if ($sign == -1) {
            $this->calculator = gmp_neg(gmp_import($binary, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN));
            return;
        }
        $this->calculator = gmp_import($binary, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);
    }


    /**
     * @param string $bytes
     * @param $outBytes
     * @return int
     * @throws \Exception
     */
    private static function checkBinary(string $bytes, &$outBytes): int
    {
        $offset = 0;
        $length = strlen($bytes);
        $firstByte = ord($bytes[0]);

        if (($firstByte & 0x80) == 0x80) {

            $end = $offset + $length;

            for ($iBval = $offset; $iBval < $end && ord($bytes[$iBval]) == 255; $iBval++) ;

            if ($iBval >= $end) {
                $outBytes = "\x01";
                return 1;
            }

            $numBytes = $end - $iBval;
            $inverse = array_new($numBytes);

            $index = 0;
            while ($index < $numBytes) {
                $inverse[$index++] = ~ord($bytes[$iBval++]);
            }
            if ($iBval == $end) throw new \Exception('Invalid binary data');

            while ($inverse[--$index] == 255) {
                $inverse[$index] = 0;
            }

            $inverse[$index]++;
            $outBytes = arr2bin($inverse);
            return -1;
        }
        $str = substr($bytes, $offset, $length);
        $outBytes = $str;

        return strlen($str) > 0 ? 1 : 0;
    }

    /**
     * @param string $str
     * @param int $radix
     * @return BigInteger
     * @throws \Exception
     */
    public static function fromNumbericString(string $str, int $radix = 10)
    {
        self::staticInitialize();

        if ($radix == 16) {
            if (strlen($str) == 0) return new static(0, "\x00");

            $sign = $str[0] === '-' ? -1 : 1;

            return new static($sign, hex2bin($sign === -1 ? substr($str, 1) : $str));
        }

        $strlen = strlen($str);
        if ($strlen == 0) throw new \Exception("Zero length BigInteger2");

        $sign = 1;

        if ($str[0] == '-') {
            if ($strlen == 1) throw new \Exception("Zero length BigInteger2");
            $sign = -1;
            $str = substr($str, 1);
        }

        $gmp = gmp_init($str, $radix);

        if ($sign === -1) $gmp = -$gmp;

        return new static($gmp);

    }

    /**
     * @return $this|BigInteger
     * @throws \Exception
     */
    public function Abs()
    {
        return $this->sign >= 0 ? $this : $this->Negate();
    }

    /**
     * @param BigInteger $value
     * @return BigInteger
     * @throws \Exception
     */
    public function Add($value): BigInteger
    {
        if ($this->sign == 0) return $value;

        return new static(gmp_add($this->calculator, $value->calculator));
    }

    /**
     * @param BigInteger $value
     * @return BigInteger
     * @throws \Exception
     */
    public function And($value): BigInteger
    {
        if ($this->sign == 0 || $value->sign == 0) return self::$Zero;

        return new static(gmp_and($this->calculator, $value->calculator));
    }


    /**
     * @param BigInteger $val
     * @return $this
     * @throws \Exception
     */
    public function AndNot(BigInteger $val)
    {
        return $this->And($val->Not());
    }

    /**
     * @param BigInteger $value
     * @return float|int
     */
    public function CompareTo($value): int
    {
        $v = gmp_cmp($this->calculator, $value->calculator);

        if ($v == 0) return 0;
        return $v > 0 ? 1 : -1;
    }

    /**
     * @param BigInteger $val
     * @return $this|BigInteger|mixed
     * @throws \Exception
     */
    public function Divide($val)
    {
        if ($val->sign == 0) throw new \Exception("Division by zero error");

        if ($this->sign == 0) return self::$Zero;
        return new static(gmp_div_q($this->calculator, $val->calculator));
    }

    /**
     * @param BigInteger $val
     * @return array
     * @throws \Exception
     */
    public function DivideAndRemainder($val): array
    {
        if ($val->sign == 0) throw new \Exception("Division by zero error");

        $biggies = gmp_div_q($this->calculator, $val->calculator);


        return [new static($biggies[0]), new static($biggies[1])];

    }

    /**
     * @param BigInteger|null $x
     * @return bool
     */
    public function Equals($x): bool
    {
        if ($x === $this) return true;

        if ($x == null)
            return false;

        return gmp_cmp($this->calculator, $x->calculator) === 0;
    }

    /**
     * @param BigInteger $value
     * @return $this|BigInteger
     * @throws \Exception
     */
    public function Gcd($value)
    {
        if ($value->sign == 0) return $this->Abs();

        if ($this->sign == 0) return $value->Abs();

        return new static(gmp_gcd($this->calculator, $value->calculator));
    }

    /**
     * @return BigInteger
     * @throws \Exception
     */
    public function Inc()
    {
        if ($this->sign == 0) return self::$One;

        return new static(gmp_add($this->calculator, self::$One->getCalculator()));
    }


    /**
     * @return float|int|mixed
     * @throws \Exception
     */
    public function getIntValue()
    {
        throw new \Exception('not impl');
    }

    /**
     * @return float|int|string
     * @throws \Exception
     */
    public function getLongValue()
    {
        throw new \Exception('not impl');
    }

    /**
     * @param BigInteger $value
     * @return BigInteger
     */
    public function Max($value): BigInteger
    {
        return $this->CompareTo($value) > 0 ? $this : $value;
    }

    /**
     * @param BigInteger $value
     * @return BigInteger
     */
    public function Min($value)
    {
        return $this->CompareTo($value) < 0 ? $this : $value;
    }

    /**
     * @param BigInteger $m
     * @return $this|BigInteger
     * @throws \Exception
     */
    public function Mod($m)
    {
        if ($m->sign < 1)
            throw new \Exception("Modulus must be positive");

        return new static(gmp_mod($this->calculator, $m->calculator));
    }

    /**
     * @param BigInteger $m
     * @return mixed
     * @throws \Exception
     */
    public function ModInverse($m)
    {
        if ($m->sign < 1) throw new \Exception("Modulus must be positive");

        return new static(gmp_invert($this->calculator, $m->calculator));
    }

    /**
     * @param BigInteger $val
     * @return $this|BigInteger|mixed
     * @throws \Exception
     */
    public function Multiply($val)
    {
        if ($val === $this)
            return $this->Square();

        if (($this->sign & $val->sign) == 0) return self::$Zero;

        return new static(gmp_mul($this->calculator, $val->calculator));
    }

    /**
     * @return $this|BigInteger|mixed
     * @throws \Exception
     */
    public function Square()
    {
        if ($this->sign == 0) return self::$Zero;


        return new static(gmp_pow($this->calculator, 2));
    }

    /**
     * @return $this|BigInteger|mixed
     * @throws \Exception
     */
    public function Sqrt()
    {
        return new static(gmp_sqrt($this->calculator));
    }

    /**
     * @return $this|BigInteger
     * @throws \Exception
     */
    public function Negate()
    {
        if ($this->sign == 0) return $this;

        return new static(-$this->calculator);
    }

    /**
     * @return $this|BigInteger
     * @throws \Exception
     */
    public function Not()
    {
        return $this->Inc()->Negate();
    }

    /**
     * @param int $exp
     * @return $this|BigInteger|mixed
     * @throws \Exception
     */
    public function Pow(int $exp)
    {
        if ($exp < 0) throw new \Exception("Negative exponent");
        if ($exp == 0) return self::$One;

        if ($this->sign == 0) return $this;

        return new static(gmp_pow($this->calculator, $exp));
    }

    /**
     * @param BigInteger $n
     * @return $this|BigInteger
     * @throws \Exception
     */
    public function Remainder($n)
    {
        if ($n->sign == 0) throw new \Exception("Division by zero error");

        if ($this->sign == 0) return self::$Zero;

        return new static(gmp_div_r($this->calculator, $n->calculator));
    }

    /**
     * @param int $n
     * @return $this|BigInteger|mixed
     * @throws \Exception
     */
    public function ShiftLeft(int $n)
    {
        if ($this->sign == 0) return self::$Zero;

        if ($n == 0) return $this;

        if ($n < 0) return $this->ShiftRight(-$n);

        return new static($this->calculator << $n);
    }

    /**
     * @param int $n
     * @return $this|BigInteger|mixed
     * @throws \Exception
     */
    public function ShiftRight(int $n)
    {
        if ($n == 0) return $this;

        if ($n < 0) return $this->ShiftLeft(-$n);

        return new static($this->calculator >> $n);
    }

    /**
     * @param BigInteger $n
     * @return $this|BigInteger
     * @throws \Exception
     */
    public function Subtract($n)
    {
        if ($n->sign == 0) return $this;

        if ($this->sign == 0) return $n->Negate();
        $gmp = gmp_sub($this->calculator, $n->calculator);

        return new static($gmp);

    }

    /**
     * @param bool $unsigned
     * @return false|string
     * @throws \Exception
     */
    public function getBinary(bool $unsigned = false)
    {
        $calculator = $this->calculator;

        $binary = gmp_export($calculator, 1, GMP_MSW_FIRST | GMP_BIG_ENDIAN);

        if ($this->sign < 0) {
            //计算补码
            if ((ord($binary[0]) & 0x80) == 0x80) $binary = "\x80" . $binary;
            bin2com($binary);
        }


        if ($unsigned) return $binary;

        if ($this->sign > 0 && (ord($binary[0]) & 0x80) == 0x80) {
            return "\x00" . $binary;
        }
        return $binary;
    }

    /**
     * @param BigInteger $value
     * @return $this|BigInteger
     * @throws \Exception
     */
    public function Or($value)
    {
        if ($this->sign == 0) return $value;

        if ($value->sign == 0) return $this;

        return new static(gmp_or($this->calculator, $value->calculator));
    }

    /**
     * @param BigInteger $value
     * @return $this|BigInteger
     * @throws \Exception
     */
    public function Xor($value)
    {
        if ($this->sign == 0) return $value;

        if ($value->sign == 0) return $this;
        return new static(gmp_xor($this->calculator, $value->calculator));
    }

    /**
     * @return int
     */
    public function getSign(): int
    {
        return $this->sign;
    }

    /**
     * @return false|float|GMP|int|resource|null
     */
    public function getCalculator()
    {
        return $this->calculator;
    }
}
