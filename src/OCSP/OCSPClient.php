<?php


namespace Jazor\OCSP;


use Exception;
use Jazor\ASN1\ASN1Reader;
use Jazor\Console;
use Jazor\Http\Request;
use Jazor\Http\Transporters\TcpTransporter;
use Jazor\NotImplementedException;
use Jazor\UnexpectedException;
use Jazor\X509\PemReader;
use Jazor\X509\X509CertificateV3;
use Jazor\X509\X509Extension;
use Jazor\X509\X509Extensions;
use Jazor\X509\X509Extensions\AccessDescription;

/**
 * Class OCSPClient
 * @link https://www.rfc-editor.org/rfc/rfc2560.html
 * @package Jazor
 */
class OCSPClient
{

    private $certificate;
    private $endpoint;
    private $issuerKeyIdentifier;

    /**
     * OCSPClient constructor.
     * @param string|X509CertificateV3 $certificate
     * @throws Exception
     */
    public function __construct($certificate)
    {
        if($certificate instanceof X509CertificateV3){
            $this->certificate = $certificate;
        }else {
            if (strpos($certificate, '-----BEGIN CERTIFICATE-----') !== false) {
                $certificate = PemReader::getPemContents($certificate, $name);
            }
            $this->certificate = X509CertificateV3::getInstance(ASN1Reader::read($certificate));
        }

        $extensions = $this->certificate->getCertificateInfo()->getExtensions();

        $this->endpoint = self::getOCSPEndPoint($extensions);
        $this->issuerKeyIdentifier = self::getKeyIdentifier($extensions);
    }

    /**
     * @param X509Extensions $extensions
     * @return string
     * @throws UnexpectedException
     */
    private static function getKeyIdentifier(X509Extensions $extensions){

        $extension = $extensions->getExtension(X509Extension::AuthorityKeyIdentifier);
        if($extension == null) throw new Exception('extension \'AuthorityKeyIdentifier\' not found');

        $extension = $extension->getContents();
        if(!($extension instanceof X509Extensions\AuthorityKeyIdentifier)) throw new UnexpectedException('expect \'AuthorityKeyIdentifier\'');
        return $extension->getKeyIdentifier();
    }

    /**
     * @param X509Extensions $extensions
     * @return string|null
     * @throws UnexpectedException
     * @throws NotImplementedException
     */
    private static function getOCSPEndPoint(X509Extensions $extensions){
        $extension = $extensions->getExtension(X509Extension::AuthorityInfoAccess);
        if($extension == null) throw new Exception('extension \'AuthorityInfoAccess\' not found');

        $extension = $extension->getContents();
        if(!($extension instanceof X509Extensions\AuthorityInfoAccess)) throw new UnexpectedException('expect \'AuthorityInfoAccess\'');
        $descriptions = $extension->getAuthorityInfoAccessSyntax();

        /**
         * @var AccessDescription $desc
         **/
        foreach ($descriptions as $desc){
            if($desc->getAccessMethod() == AccessDescription::ID_AD_OCSP) return $desc->getAccessLocation()->getValue();
        }
        throw new Exception('no OCSP endpoint specified');
    }

    public function verify(){

        $certInfo = $this->certificate->getCertificateInfo();
        $serialNumber = $certInfo->getId();
        $issuer = $certInfo->getIssuer();
        $issuerKeyIdentifier = $this->issuerKeyIdentifier;

        $ocspRequest = new OCSPRequest($serialNumber, $issuer, $issuerKeyIdentifier);

        $body = $ocspRequest->getEncoded();

        $requestUrl = rtrim($this->endpoint, '/') . '/' . urlencode(base64_encode($body));

        $request = new Request($requestUrl);

        $response = (new TcpTransporter())->execute($request);

        $asn1 = ASN1Reader::read($response->getBody());

        return OCSPResponse::getInstance($asn1);
    }
}
