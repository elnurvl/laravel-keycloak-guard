<?php

declare(strict_types=1);

namespace KeycloakGuard\Tests\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use KeycloakGuard\Tests\Models\User;

class UserFactory extends Factory
{
    protected $model = User::class;

    public function definition(): array
    {
        return [
            'username' => $this->faker->userName,
        ];
    }
}
