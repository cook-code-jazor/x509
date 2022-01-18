<?php

namespace Jazor\Security\DSA;

use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\Security\AsymmetricKeyIdentifier;

class DSAKeyIdentifier extends AsymmetricKeyIdentifier
{
    private DSADomainParameters $domainParameters;

    /**
     * @param string $algorithm
     * @param DSADomainParameters $domainParameters
     */
    public function __construct(string $algorithm, DSADomainParameters $domainParameters)
    {
        parent::__construct($algorithm);
        $this->domainParameters = $domainParameters;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();

        $gen->ObjectIdentifier($this->getAlgorithm());
        $gen->Object($this->domainParameters);
        $gen->generate();
    }

}
