<?php

declare(strict_types=1);

namespace KeycloakGuard\Tests;

use Firebase\JWT\JWT;
use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use KeycloakGuard\KeycloakGuardServiceProvider;
use KeycloakGuard\PublicKey;
use KeycloakGuard\Tests\Factories\UserFactory;
use KeycloakGuard\Tests\Models\User;
use OpenSSLAsymmetricKey;
use Orchestra\Testbench\TestCase as Orchestra;
use Ramsey\Uuid\Uuid;

class TestCase extends Orchestra
{
    public OpenSSLAsymmetricKey $privateKey;
    public array $payload;
    public string $token;
    public string $kid;

    protected function setUp(): void
    {
        // Prepare credentials
        parent::setUp();

        $this->prepareCredentials();

        $this->withoutExceptionHandling();

        // bootstrap
        $this->setUpDatabase($this->app);

        // Default user, same as jwt token
        $this->user = UserFactory::new()->create([
            'username' => 'johndoe'
        ]);
    }

    protected function prepareCredentials(string $encryptionAlgorithm = 'RS256', ?array $openSSLConfig = null, ?string $realm = null): void
    {
        // Prepare private/public keys and a default JWT token, with a simple payload
        if (!$openSSLConfig) {
            $openSSLConfig = [
                'digest_alg' => 'sha256',
                'private_key_bits' => 1024,
                'private_key_type' => OPENSSL_KEYTYPE_RSA
            ];
        }

        $this->privateKey = openssl_pkey_new($openSSLConfig);

        $publicKey = openssl_pkey_get_details($this->privateKey)['key'];

        $realm ??= 'test';
        $baseUrl = 'http://keycloak.test/realms/'.$realm;

        $this->kid = Uuid::uuid4()->toString();

        Http::fake([
            "$baseUrl/.well-known/openid-configuration" => Http::response([
                'jwks_uri' => "$baseUrl/protocol/openid-connect/certs"
            ]),
            "$baseUrl/protocol/openid-connect/certs" => Http::response([
                'keys' => [ PublicKey::convertPublicKeyToJWK($publicKey, $encryptionAlgorithm, $this->kid) ]
            ]),
        ]);

        $this->payload = [
            'iss' => $baseUrl,
            'preferred_username' => 'johndoe',
            'resource_access' => ['myapp-backend' => []]
        ];

        $this->token = JWT::encode($this->payload, $this->privateKey, $encryptionAlgorithm, $this->kid);
    }

    // Default configs to make it running
    protected function defineEnvironment($app): void
    {
        $app['config']->set('auth.defaults.guard', 'api');
        $app['config']->set('auth.providers.users.model', User::class);

        $app['config']->set('auth.guards.api', [
            'driver' => 'keycloak',
            'provider' => 'users'
        ]);

        $app['config']->set('keycloak', [
            'key_cache_lifetime' => 0,
            'user_provider_credential' => 'username',
            'token_principal_attribute' => 'preferred_username',
            'append_decoded_token' => false,
            'allowed_resources' => 'myapp-backend',
            'ignore_resources_validation' => false,
        ]);
    }

    protected function setUpDatabase(Application $app): void
    {
        $app['db']->connection()->getSchemaBuilder()->create('users', function (Blueprint $table) {
            $table->increments('id');
            $table->string('username');
            $table->timestamps();
        });
    }

    protected function getPackageProviders($app): array
    {
        Route::any('/foo/secret', 'KeycloakGuard\Tests\Controllers\FooController@secret')->middleware(Authenticate::class);
        Route::any('/foo/public', 'KeycloakGuard\Tests\Controllers\FooController@public');

        return [KeycloakGuardServiceProvider::class];
    }

    // Build a different token with custom payload
    protected function buildCustomToken(array $payload, string $encryptionAlgorithm = 'RS256'): void
    {
        $payload = array_replace($this->payload, $payload);

        $this->token = JWT::encode($payload, $this->privateKey, $encryptionAlgorithm, $this->kid);
    }

    // Setup default token, for the default user
    public function withKeycloakToken(): self
    {
        $this->withToken($this->token);

        return $this;
    }
}
