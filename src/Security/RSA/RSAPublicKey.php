<?php


namespace Jazor\Security\RSA;


use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Integer;
use Jazor\Security\AlgorithmIdentifier;
use Jazor\Security\AsymmetricKey;
use Jazor\Security\AsymmetricKeyIdentifier;

class RSAPublicKey extends AsymmetricKey
{

    private $modulus;
    private $exponent;

    /**
     * RSAPublicKey constructor.
     * @param AsymmetricKeyIdentifier $algorithm
     * @param $exponent
     * @param $modulus
     */
    public function __construct(AsymmetricKeyIdentifier $algorithm, $exponent, $modulus)
    {
        parent::__construct($algorithm, null);

        $this->modulus = $modulus;
        $this->exponent = $exponent;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public function getEncoded()
    {
        $alg = $this->getAlgorithm();
        $gen = ASN1SequenceGenerator::create();
        $gen->Sequence(function (ASN1SequenceGenerator $seq) use ($alg){
            $seq->ObjectIdentifier($alg->getAlgorithm());
            $seq->Null();
        });

        $pk = ASN1SequenceGenerator::create();

        $pk->Integer($this->modulus);
        $pk->Integer($this->exponent);

        $gen->BitString($pk->generate());
        return $gen->generate();
    }

    /**
     * @return mixed
     */
    public function getModulus()
    {
        return $this->modulus;
    }


    /**
     * @return mixed
     */
    public function getExponent()
    {
        return $this->exponent;
    }

    public function __toString()
    {
        return sprintf("Exponent = %s\r\nModulus = 0x%s", $this->exponent, limit_bin2hex($this->modulus));
    }
}
