<?php
namespace Jazor\Security\Oid;

class Oid
{
    private $oid = '';
    private $friendlyName = '';

    /**
     * @return string
     */
    public function getId(){
        return $this->oid;
    }

    /**
     * @return string
     */
    public function getFriendlyName()
    {
        return $this->friendlyName;
    }
    public function __construct($oid, $friendlyName = '')
    {
        $this->oid = $oid;
        $this->friendlyName = $friendlyName;
    }

    public function branch($branch){
        return new Oid($this->oid . '.' . $branch);
    }
}
