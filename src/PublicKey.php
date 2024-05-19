<?php

declare(strict_types=1);

namespace KeycloakGuard;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use KeycloakGuard\Exceptions\PublicKeyException;
use KeycloakGuard\Exceptions\TokenException;
use Ramsey\Uuid\Uuid;

class PublicKey
{
    /**
     * @param string|null $issuer
     *
     * @return array<Key>
     */
    public static function getPublicKey(?string $issuer): array
    {
        $cacheLifetime = config('keycloak.key_cache_lifetime', 0);

        return Cache::remember('laravel-keycloak-guard:'.$issuer, $cacheLifetime, function () use ($issuer) {
            $jwks = self::fetchJWKS($issuer);

            return JWK::parseKeySet($jwks);
        });
    }

    /**
     * @throws PublicKeyException
     */
    public static function convertPublicKeyToJWK(
        string $publicKeyPem,
        string $alg = 'RS256',
        string $kid = null,
        string $use = 'sig'
    ): array {
        $publicKey = openssl_pkey_get_public($publicKeyPem);

        if (!$publicKey) {
            throw new PublicKeyException("Unable to load public key.");
        }

        $details = openssl_pkey_get_details($publicKey);

        $jwk = [
            'kid' => $kid ?? Uuid::uuid4()->toString(),
            'alg' => $alg,
            'use' => $use,
        ];

        switch ($details['type']) {
            case OPENSSL_KEYTYPE_RSA:
                $jwk['kty'] = 'RSA';
                $jwk['n'] = self::base64urlEncode($details['rsa']['n']);
                $jwk['e'] = self::base64urlEncode($details['rsa']['e']);

                break;
            case OPENSSL_KEYTYPE_DSA:
                $jwk['kty'] = 'DSA';
                $jwk['p'] = self::base64urlEncode($details['dsa']['p']);
                $jwk['q'] = self::base64urlEncode($details['dsa']['q']);
                $jwk['g'] = self::base64urlEncode($details['dsa']['g']);
                $jwk['y'] = self::base64urlEncode($details['dsa']['pub_key']);

                break;
            case OPENSSL_KEYTYPE_EC:
                $jwk['kty'] = 'EC';
                $jwk['crv'] = self::getEcCurveName($details['ec']['curve_name']);
                $jwk['x'] = self::base64urlEncode($details['ec']['x']);
                $jwk['y'] = self::base64urlEncode($details['ec']['y']);

                break;
            case OPENSSL_KEYTYPE_DH:
                $jwk['kty'] = 'DH';
                $jwk['p'] = self::base64urlEncode($details['dh']['p']);
                $jwk['g'] = self::base64urlEncode($details['dh']['g']);
                $jwk['y'] = self::base64urlEncode($details['dh']['pub_key']);

                break;
            default:
                throw new PublicKeyException("Unsupported key type.");
        }

        return $jwk;
    }

    /**
     * @param string|null $issuer
     *
     * @return array
     */
    private static function fetchJWKS(?string $issuer): array
    {
        // Try the already-known JWK URI first
        $jwksUri = $issuer.'/protocol/openid-connect/certs';

        try {
            $jwksResponse = Http::get($jwksUri);
        } catch (ConnectionException) {
            throw new TokenException("Token does not contain a valid issuer");
        }

        if ($jwksResponse->successful()) {
            return $jwksResponse->json();
        }

        // Obtain the URI from the discovery document if the initially assumed one was not valid
        $wellKnownUrl = $issuer.'/.well-known/openid-configuration';
        $wellKnownResponse = Http::get($wellKnownUrl);

        if (!$wellKnownResponse->successful()) {
            throw new PublicKeyException("Unable to fetch well-known configuration.");
        }

        $wellKnownConfig = $wellKnownResponse->json();

        if (!isset($wellKnownConfig['jwks_uri'])) {
            throw new PublicKeyException("JWKS URI not found in well-known configuration.");
        }

        $jwksUri = $wellKnownConfig['jwks_uri'];
        $jwksResponse = Http::get($jwksUri);

        if (!$jwksResponse->successful()) {
            throw new PublicKeyException("Unable to fetch JWKS.");
        }

        return $jwksResponse->json();
    }

    private static function base64urlEncode($data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function getEcCurveName(string $curveName): string
    {
        $curveNames = [
            'prime256v1' => 'P-256',
            'secp256k1' => 'secp256k1',
            'secp384r1' => 'P-384',
            'secp521r1' => 'P-521',
        ];

        return $curveNames[$curveName] ?? $curveName;
    }
}
