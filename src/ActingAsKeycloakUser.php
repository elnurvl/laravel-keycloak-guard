<?php

declare(strict_types=1);

namespace KeycloakGuard;

use Firebase\JWT\JWT;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Ramsey\Uuid\Uuid;

trait ActingAsKeycloakUser
{
    public function actingAsKeycloakUser(Authenticatable|string|null $user = null, array $payload = []): self
    {
        if (!$user) {
            Config::set('keycloak.load_user_from_database', false);
        }

        $token = $this->generateKeycloakToken($user, $payload);

        $this->withHeader('Authorization', 'Bearer '.$token);

        return $this;
    }

    public function generateKeycloakToken(Authenticatable|string|null $user = null, array $payload = []): string
    {
        $alg = 'RS256';
        $privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);

        $publicKey = openssl_pkey_get_details($privateKey)['key'];

        $kid = Uuid::uuid4()->toString();

        $baseUrl = 'http://keycloak.test/realms/laravel';

        Http::fake([
            "$baseUrl/.well-known/openid-configuration" => Http::response([
                'jwks_uri' => "$baseUrl/protocol/openid-connect/certs"
            ]),
            "$baseUrl/protocol/openid-connect/certs" => Http::response([
                'keys' => [ PublicKey::convertPublicKeyToJWK($publicKey, $alg, $kid) ]
            ]),
        ]);

        $iat = time();
        $exp = time() + 300;
        $resourceAccess = [config('keycloak.allowed_resources') => []];

        $principal = Config::get('keycloak.token_principal_attribute');
        $credential = Config::get('keycloak.user_provider_credential');
        $payload = array_merge([
            'iss' => $baseUrl,
            'iat' => $iat,
            'exp' => $exp,
            $principal => is_string($user) ? $user : $user->$credential ?? config('keycloak.preferred_username'),
            'resource_access' => $resourceAccess
        ], $payload);

        return JWT::encode($payload, $privateKey, $alg, $kid);
    }
}
