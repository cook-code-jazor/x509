<?php
namespace Jazor\ASN1;

use Throwable;

class DerEncodingInvalidException extends \Exception
{
    public function __construct($message = "", $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
