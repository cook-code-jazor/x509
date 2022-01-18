<?php


namespace Jazor\X509\X509Extensions;


class FreshestCrl extends CrlDistributionPoints
{

    public function __construct(array $distributionPoints)
    {
        parent::__construct($distributionPoints);
    }
}
