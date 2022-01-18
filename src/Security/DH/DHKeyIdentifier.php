<?php

namespace Jazor\Security\DH;

use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\Security\AsymmetricKeyIdentifier;

class DHKeyIdentifier extends AsymmetricKeyIdentifier
{
    private DHDomainParameters $domainParameters;

    /**
     * @param string $algorithm
     * @param DHDomainParameters $domainParameters
     */
    public function __construct(string $algorithm, DHDomainParameters $domainParameters)
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

    /**
     * @return DHDomainParameters
     */
    public function getDomainParameters(): DHDomainParameters
    {
        return $this->domainParameters;
    }
}
