<?php


namespace Jazor\X509\X509Extensions\CrlDistributionPoints;


class ReasonFlags
{
    const unused = 128;
    const keyCompromise = 64;
    const cACompromise = 32;
    const affiliationChanged = 16;
    const superseded = 8;
    const cessationOfOperation = 4;
    const certificateHold = 2;
    const privilegeWithdrawn = 1;
    const aACompromise = 32768;
}
