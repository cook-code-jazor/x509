<?php


namespace Jazor\OCSP;


class OCSPResponseStatus
{
    const successful = 0;
    const malformedRequest = 1;
    const internalError = 2;
    const tryLater = 3;
    const sigRequired = 5;
    const unauthorized = 6;

    public static array $Status = ['successful', 'malformedRequest', 'internalError', 'tryLater', null, 'sigRequired', 'unauthorized'];
}
