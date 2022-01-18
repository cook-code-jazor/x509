<?php

namespace Jazor\X509;

use Jazor\ASN1\ASN1Encodable;
use Jazor\ASN1\ASN1Reader;
use Jazor\ASN1\ASN1SequenceGenerator;
use Jazor\ASN1\Objects\ASN1Sequence;
use Jazor\Console;
use Jazor\NotImplementedException;
use Jazor\NotSupportedException;

/**
 * Class X509Extension
 * @package Jazor\X509
 */
class X509Extension implements ASN1Encodable
{
    const SubjectDirectoryAttributes = '2.5.29.9';
    const SubjectKeyIdentifier = '2.5.29.14';
    const KeyUsage = '2.5.29.15';
    const PrivateKeyUsagePeriod = '2.5.29.16';
    const SubjectAlternativeName = '2.5.29.17';
    const IssuerAlternativeName = '2.5.29.18';
    const BasicConstraints = '2.5.29.19';
    const CrlNumber = '2.5.29.20';
    const ReasonCode = '2.5.29.21';
    const InstructionCode = '2.5.29.23';
    const InvalidityDate = '2.5.29.24';
    const DeltaCrlIndicator = '2.5.29.27';
    const IssuingDistributionPoint = '2.5.29.28';
    const CertificateIssuer = '2.5.29.29';
    const NameConstraints = '2.5.29.30';
    const CrlDistributionPoints = '2.5.29.31';
    const CertificatePolicies = '2.5.29.32';
    const PolicyMappings = '2.5.29.33';
    const AuthorityKeyIdentifier = '2.5.29.35';
    const PolicyConstraints = '2.5.29.36';
    const ExtendedKeyUsage = '2.5.29.37';
    const FreshestCrl = '2.5.29.46';
    const InhibitAnyPolicy = '2.5.29.54';
    const TargetInformation = '2.5.29.55';
    const NoRevAvail = '2.5.29.56';
    const ExpiredCertsOnCrl = '2.5.29.60';
    const AuthorityInfoAccess = '1.3.6.1.5.5.7.1.1';
    const BiometricInfo = '1.3.6.1.5.5.7.1.2';
    const QCStatements = '1.3.6.1.5.5.7.1.3';
    const AuditIdentity = '1.3.6.1.5.5.7.1.4';
    const SubjectInfoAccess = '1.3.6.1.5.5.7.1.11';
    const LogoType = '1.3.6.1.5.5.7.1.12';
    const SCTList = '1.3.6.1.4.1.11129.2.4.2';
    const EntrustVersionInfo = '1.2.840.113533.7.65.0';
    const AutoEnrollCtlUsage = '1.3.6.1.4.1.311.20.1';
    const CertificateType = '1.3.6.1.4.1.311.20.2';
    const EnrollmentAgent = '1.3.6.1.4.1.311.20.2.1';
    const KPSmartCardLogin = '1.3.6.1.4.1.311.20.2.2';
    const NTPrincipalName = '1.3.6.1.4.1.311.20.2.3';
    const CertManifold = '1.3.6.1.4.1.311.20.3';
    const CaKeyCertIndexPair = '1.3.6.1.4.1.311.21.1';
    const NetscapeCertType = '2.16.840.1.113730.1.1';
    const HashedRootKey = '2.23.42.7.0';
    const SMIMECapabilities = '1.2.840.113549.1.9.15';
    const TLSFeatures = '1.3.6.1.5.5.7.1.24';
    const NetscapeComment = '2.16.840.1.113730.1.13';
    const UnKnown_01 = '1.3.6.1.4.1.5315.100.5.6';
    const UnKnown_02 = '1.3.6.1.4.1.5315.100.5.9';
    const UnKnown_03 = '1.3.6.1.4.1.5315.100.2.4';
    const UnKnown_04 = '1.3.6.1.4.1.5315.100.2.1';
    const UnKnown_05 = '2.16.840.1.113731.9';
    const UnKnown_06 = '1.3.6.1.4.1.311.21.10'; //SEQ->SEQ[0...MAX]->OID
    const UnKnown_07 = '1.3.6.1.4.1.311.21.7'; //SEQ->OID+INT+INT
    const UnKnown_08 = '1.3.6.1.4.1.5315.100.5.8';
    const UnKnown_10 = '1.3.6.1.4.1.5315.100.5.12';
    const UnKnown_11 = '1.2.86.11.7.2';
    const UnKnown_12 = '1.2.86.11.7.3';

    public static array $KnownNames = [
        self::SubjectDirectoryAttributes => 'SubjectDirectoryAttributes',
        self::SubjectKeyIdentifier => 'SubjectKeyIdentifier',
        self::KeyUsage => 'KeyUsage',
        self::PrivateKeyUsagePeriod => 'PrivateKeyUsagePeriod',
        self::SubjectAlternativeName => 'SubjectAlternativeName',
        self::IssuerAlternativeName => 'IssuerAlternativeName',
        self::BasicConstraints => 'BasicConstraints',
        self::CrlNumber => 'CrlNumber',
        self::ReasonCode => 'ReasonCode',
        self::InstructionCode => 'InstructionCode',
        self::InvalidityDate => 'InvalidityDate',
        self::DeltaCrlIndicator => 'DeltaCrlIndicator',
        self::IssuingDistributionPoint => 'IssuingDistributionPoint',
        self::CertificateIssuer => 'CertificateIssuer',
        self::NameConstraints => 'NameConstraints',
        self::CrlDistributionPoints => 'CrlDistributionPoints',
        self::CertificatePolicies => 'CertificatePolicies',
        self::PolicyMappings => 'PolicyMappings',
        self::AuthorityKeyIdentifier => 'AuthorityKeyIdentifier',
        self::PolicyConstraints => 'PolicyConstraints',
        self::ExtendedKeyUsage => 'ExtendedKeyUsage',
        self::FreshestCrl => 'FreshestCrl',
        self::InhibitAnyPolicy => 'InhibitAnyPolicy',
        self::TargetInformation => 'TargetInformation',
        self::NoRevAvail => 'NoRevAvail',
        self::ExpiredCertsOnCrl => 'ExpiredCertsOnCrl',
        self::AuthorityInfoAccess => 'AuthorityInfoAccess',
        self::BiometricInfo => 'BiometricInfo',
        self::QCStatements => 'QCStatements',
        self::AuditIdentity => 'AuditIdentity',
        self::SubjectInfoAccess => 'SubjectInfoAccess',
        self::LogoType => 'LogoType',
        self::SCTList => 'SCTList',
        self::EntrustVersionInfo => 'EntrustVersionInfo',
        self::AutoEnrollCtlUsage => 'AutoEnrollCtlUsage',
        self::CertificateType => 'CertificateType',
        self::EnrollmentAgent => 'EnrollmentAgent',
        self::KPSmartCardLogin => 'KPSmartCardLogin',
        self::NTPrincipalName => 'NTPrincipalName',
        self::CertManifold => 'CertManifold',
        self::CaKeyCertIndexPair => 'CaKeyCertIndexPair',
        self::NetscapeCertType => 'NetscapeCertType',
        self::HashedRootKey => 'HashedRootKey',
        self::SMIMECapabilities => 'SMIMECapabilities',
        self::NetscapeComment => 'NetscapeComment',
        self::TLSFeatures => 'TLSFeatures',
        self::UnKnown_01 => 'UnKnown_01',
        self::UnKnown_02 => 'UnKnown_02',
        self::UnKnown_03 => 'UnKnown_03',
        self::UnKnown_04 => 'UnKnown_04',
        self::UnKnown_05 => 'UnKnown_05',
        self::UnKnown_06 => 'UnKnown_06',
        self::UnKnown_07 => 'UnKnown_07',
        self::UnKnown_08 => 'UnKnown_08',
        self::UnKnown_10 => 'UnKnown_10',
        self::UnKnown_11 => 'UnKnown_11',
        self::UnKnown_12 => 'UnKnown_12',
    ];

    private string $oid;
    private $contents;
    private bool $isCritical;
    private bool $isCriticalSet = false;

    public function __construct($oid, $value, $isCritical = false, $isCriticalSet = false)
    {
        $this->oid = $oid;
        $this->contents = $value;
        $this->isCritical = $isCritical;
        $this->isCriticalSet = $isCriticalSet;
    }

    public function getEncoded()
    {
        $gen = ASN1SequenceGenerator::create();
        $gen->ObjectIdentifier($this->oid);
        if ($this->isCritical || $this->isCriticalSet) {
            $gen->Boolean($this->isCritical);
        }
        if ($this->contents instanceof ASN1Encodable) {
            $gen->OctetString($this->contents->getEncoded());
        } else {
            $gen->OctetString($this->contents);
        }
        return $gen->generate();
    }

    private function getContentsString(){
        return $this->contents instanceof ASN1Encodable ? (string)$this->contents : '0x' . limit_bin2hex($this->contents);
    }
    public function __toString()
    {
        if(!$this->isCriticalSet){

            return sprintf("%s, OID = %s\r\n%s",
                self::$KnownNames[$this->oid],
                $this->oid,
                indent($this->getContentsString(), 2)
            );
        }
        return sprintf("%s, Critical = %s, OID = %s\r\n%s",
            self::$KnownNames[$this->oid] ?? $this->oid,
            $this->isCritical ? 'true' : 'false',
            $this->oid,
            indent($this->getContentsString(), 2)
        );
    }

    public static function getInstance(ASN1Sequence $seq)
    {
        $isCritical = false;
        $isCriticalSet = false;
        $oid = $seq[0]->getValue();
        $valueIndex = 1;
        if (isset($seq[2])) {
            $isCritical = $seq[1]->getValue();
            $valueIndex = 2;
            $isCriticalSet = true;
        }
        $value = $seq[$valueIndex]->getContents();


        if (!isset(self::$KnownNames[$oid])) throw new NotSupportedException('UnKnown OID(' . $oid . ')');

        $class = 'Jazor\X509\X509Extensions\\' . self::$KnownNames[$oid];

        if (!class_exists($class)) {
            switch ($oid){
                case self::CertificateType:
                case self::CaKeyCertIndexPair:
                case self::NetscapeCertType:
                case self::NetscapeComment:
                case self::UnKnown_01:
                case self::UnKnown_02:
                case self::UnKnown_03:
                case self::UnKnown_04:
                case self::UnKnown_05:
                    $value = ASN1Reader::read($value);
                    break;
            }
            return new static($oid, $value, $isCritical, $isCriticalSet);
        }
        return new static($oid, call_user_func($class . '::getInstance', $value), $isCritical, $isCriticalSet);
    }

    /**
     * @return string
     */
    public function getOid(): string
    {
        return $this->oid;
    }

    /**
     * @return string|ASN1Encodable
     */
    public function getContents()
    {
        return $this->contents;
    }

    /**
     * @return bool
     */
    public function getIsCritical(): bool
    {
        return $this->isCritical;
    }
}
