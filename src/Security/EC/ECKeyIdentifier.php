<?php

namespace Jazor\Security\EC;

use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\Security\AsymmetricKeyIdentifier;

class ECKeyIdentifier extends AsymmetricKeyIdentifier
{
    private ?string $curve;
    private ?ECParameters $parameters;

    /**
     * ECKeyIdentifier constructor.
     * @param string $algorithm
     * @param string|null $curve
     * @param ECParameters|null $parameters
     */
    public function __construct(string $algorithm, ?string $curve, ?ECParameters $parameters = null)
    {
        parent::__construct($algorithm);
        $this->curve = $curve;
        $this->parameters = $parameters;
    }

    /**
     * @return string|null
     */
    public function getCurve()
    {
        return $this->curve;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();

        $gen->ObjectIdentifier($this->getAlgorithm());
        if($this->curve != null) $gen->ObjectIdentifier($this->curve);
        if($this->parameters != null) $gen->Object($this->parameters);
        $gen->generate();
    }

    /**
     * @return ECParameters|null
     */
    public function getParameters(): ?ECParameters
    {
        return $this->parameters;
    }
}
