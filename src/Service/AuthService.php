<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\RequestStack;

class AuthService
{
    private $requestStack;

    public function __construct(RequestStack $requestStack)
    {
        $this->requestStack = $requestStack;
    }

    public function getUser(): ?array
    {
        return $this->requestStack->getSession()->get('user');
    }

    public function isLoggedIn(): bool
    {
        return $this->getUser() !== null;
    }

    public function isAdmin(): bool
    {
        $user = $this->getUser();
        return $user !== null && $user['type'] === 'admin';
    }

    public function isClient(): bool
    {
        $user = $this->getUser();
        return $user !== null && $user['type'] === 'client';
    }
}
