<?php


namespace Jazor\Security\RSA;


use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\Console;
use Jazor\Security\AlgorithmIdentifier;
use Jazor\Security\AsymmetricKey;

class RSAPrivateKey extends AsymmetricKey
{
    private RSAPublicKey $publicKey;
    private $d; //privateExponent
    private $p; //prime1
    private $q; //prime2
    private $dp; //exponent1 d mod (p-1)
    private $dq; //exponent2 d mod (q-1)
    private $qp; //coefficient (inverse of q) mod p

    /**
     * RSAPublicKey constructor.
     * @param RSAKeyIdentifier $algorithm
     * @param $exponent
     * @param $modulus
     * @param $d
     * @param $p
     * @param $q
     * @param $dp
     * @param $dq
     * @param $qp
     */
    public function __construct(RSAKeyIdentifier $algorithm, RSAPublicKey $publicKey, $d, $p, $q, $dp, $dq, $qp)
    {
        parent::__construct($algorithm, null);

        $this->publicKey = $publicKey;
        $this->d = $d;
        $this->p = $p;
        $this->q = $q;
        $this->dp = $dp;
        $this->dq = $dq;
        $this->qp = $qp;
    }

    /**
     * @return mixed
     */
    public function getD()
    {
        return $this->d;
    }

    /**
     * @return mixed
     */
    public function getP()
    {
        return $this->p;
    }

    /**
     * @return mixed
     */
    public function getQ()
    {
        return $this->q;
    }

    /**
     * @return mixed
     */
    public function getDp()
    {
        return $this->dp;
    }

    /**
     * @return mixed
     */
    public function getDq()
    {
        return $this->dq;
    }

    /**
     * @return mixed
     */
    public function getQp()
    {
        return $this->qp;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->Integer("\x00");
        $gen->Integer($this->publicKey->getModulus());

        $gen->Integer($this->publicKey->getExponent());
        $gen->Integer($this->d);
        $gen->Integer($this->p);
        $gen->Integer($this->q);
        $gen->Integer($this->dp);
        $gen->Integer($this->dq);
        $gen->Integer($this->qp);

        return $gen->generate();
    }
    public function __toString()
    {
        return sprintf(
            "privateExponent = 0x%s\r\nprime1 = 0x%s\r\nprime2= 0x%s\r\nexponent1= 0x%s\r\nexponent2= 0x%s\r\ncoefficient= 0x%s",
            limit_bin2hex($this->d),
            limit_bin2hex($this->p),
            limit_bin2hex($this->q),
            limit_bin2hex($this->dp),
            limit_bin2hex($this->dq),
            limit_bin2hex($this->qp)
        );
    }

    /**
     * @return RSAPublicKey
     */
    public function getPublicKey(): RSAPublicKey
    {
        return $this->publicKey;
    }
}
