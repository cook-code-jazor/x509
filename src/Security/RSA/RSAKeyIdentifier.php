<?php

namespace Jazor\Security\RSA;

use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\Security\AsymmetricKeyIdentifier;

class RSAKeyIdentifier extends AsymmetricKeyIdentifier
{
    /**
     * @param string $algorithm
     */
    public function __construct(string $algorithm)
    {
        parent::__construct($algorithm);
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();

        $gen->ObjectIdentifier($this->getAlgorithm());
        $gen->Null();
        $gen->generate();
    }
}
